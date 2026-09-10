"""One record of every file an install touched, so an uninstall can be exact.

WHY this is a single file and not five per-feature ones:

Before this module an install left four independent traces -- a numbered
settings.json backup, a byte-exact baseline, a stashed statusLine, and a
bin-link.json listing the symlinks -- each written by whichever code path
happened to need it and each recovered by a different rule. Together they could
not answer the only question an uninstall actually has: *which files did we
touch, and are they still the files we left?*

That question is the whole point, and the answer decides which of two very
different undos is correct. A backup is NOT a safe thing to restore. The
ordinary life of an install is: wire the hooks in March; spend the next six
months adding MCP servers, permissions and another tool's hooks to the same
settings.json; uninstall in September. Restoring March's copy over that is a
silent, total loss of six months of configuration -- far worse than the stray
hook entry an imperfect surgical removal might leave behind.

So the manifest does not exist to enable a blind restore. It exists to make the
SURGICAL removal exact rather than heuristic, and to let the caller PROVE, per
file, whether a verbatim restore also happens to be safe:

    current checksum == the checksum we wrote  ->  nobody has touched the file
                                                   since our write, so the
                                                   pre-install bytes are a
                                                   provably perfect undo.
    current checksum != the checksum we wrote  ->  somebody has. Remove only our
                                                   own entries, keep their
                                                   edits, and say so out loud.

Nothing here raises. It is consulted on the uninstall path -- the path that runs
when something has already gone wrong -- and a traceback out of a bookkeeping
file would take the recovery down with it. A missing, truncated or hand-mangled
manifest degrades to the verdict "unknown", which is exactly the value that
makes every caller take the conservative branch.

The file lives under state/ and is never committed: it is a list of absolute
paths on one machine, which is the definition of what state/ is for.
"""

from __future__ import annotations

import hashlib
import itertools
import json
import os
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

__all__ = ["MANIFEST_NAME", "SCHEMA_VERSION", "ACTIONS", "KINDS",
           "Manifest", "digest", "manifest_path"]

MANIFEST_NAME = "install-manifest.json"
SCHEMA_VERSION = 1

#: What we did to a file. `created` and `modified` are the two an undo can
#: reverse by writing bytes back; `stashed` and `linked` are reversed by
#: removing what we made. Recorded rather than re-derived, because by uninstall
#: time the evidence for "did this file exist before us?" is gone.
ACTIONS = ("created", "modified", "stashed", "linked")

#: Which concern the file belongs to. The kind is part of an entry's identity,
#: not decoration: state/ holds a baseline AND a displaced-statusLine stash for
#: the same settings file, and a path on its own cannot say which one a caller
#: is asking about.
KINDS = ("settings", "baseline", "statusline-stash", "config", "symlink",
         "shell-rc")

_TMP_SEQ = itertools.count()


def manifest_path(install_dir: Path) -> Path:
    return Path(install_dir) / "state" / MANIFEST_NAME


def digest(path: Any) -> Optional[str]:
    """sha256 of a file's BYTES, or None when there is nothing to read.

    Bytes, not parsed JSON. The question this answers is "has this file changed
    since we wrote it", and a settings.json somebody re-indented by hand IS
    changed -- it carries their formatting now, and a restore that flattened it
    would be a change we made without being asked.

    Streamed rather than read whole: a settings file is small, but this is also
    pointed at shell rc files, which can run to tens of KB of config that there
    is no reason to hold twice in memory.
    """
    try:
        digester = hashlib.sha256()
        with open(str(path), "rb") as handle:
            for chunk in iter(lambda: handle.read(1 << 16), b""):
                digester.update(chunk)
        return digester.hexdigest()
    except Exception:
        # Absent, unreadable, a dangling symlink, a directory. All of them mean
        # the same thing to every caller: we cannot prove anything about it.
        return None


def _key(path: Any) -> str:
    try:
        return os.path.normpath(str(path))
    except Exception:
        return str(path)


def _link_target(path: Any) -> Optional[str]:
    """Where a symlink points, WITHOUT following it. None if it is not one.

    readlink rather than realpath, deliberately: a link we made whose target
    directory has since been moved away is still our link, and resolving it
    would erase the only evidence of that.
    """
    try:
        if not os.path.islink(str(path)):
            return None
        return os.readlink(str(path))
    except Exception:
        return None


class Manifest:
    """The install record. Load it, record into it, save it. Never raises."""

    def __init__(self, path: Path, entries: Optional[List[Dict[str, Any]]] = None,
                 status: str = "ok") -> None:
        self.path = Path(path)
        self.entries: List[Dict[str, Any]] = list(entries or [])
        #: ok | absent | unreadable. `unreadable` is kept distinct from
        #: `absent` because they call for different words to the user: one is a
        #: fresh machine, the other is a file worth mentioning before we
        #: overwrite it.
        self.status = status

    # -- loading ---------------------------------------------------------

    @classmethod
    def load(cls, install_dir: Path) -> "Manifest":
        path = manifest_path(install_dir)
        try:
            if not path.is_file():
                return cls(path, [], "absent")
        except Exception:
            return cls(path, [], "absent")
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            # Truncated by a full disk, hand-edited, or from a future schema we
            # cannot read. Treated as no record at all, which makes every
            # verdict "unknown" and every caller conservative -- the correct
            # failure, and the one the class docstring promises.
            return cls(path, [], "unreadable")
        entries = data.get("entries") if isinstance(data, dict) else None
        if not isinstance(entries, list):
            return cls(path, [], "unreadable")
        clean: List[Dict[str, Any]] = []
        for entry in entries:
            # A hand-mangled list can hold anything; keep only rows that carry
            # the one field every lookup needs.
            if isinstance(entry, dict) and isinstance(entry.get("path"), str) \
                    and entry["path"]:
                clean.append(dict(entry))
        return cls(path, clean, "ok")

    # -- lookup ----------------------------------------------------------

    def entry(self, path: Any, kind: Optional[str] = None) -> Optional[Dict[str, Any]]:
        want = _key(path)
        for entry in self.entries:
            if _key(entry.get("path")) != want:
                continue
            if kind is not None and entry.get("kind") != kind:
                continue
            return entry
        return None

    def of_kind(self, kind: str) -> List[Dict[str, Any]]:
        return [e for e in self.entries if e.get("kind") == kind]

    def verdict(self, path: Any, kind: Optional[str] = None) -> Dict[str, Any]:
        """Has this file changed since we wrote it?

        States, and what each one licenses a caller to do:

          unknown    no usable record. Surgical removal only; claim nothing.
          missing    we wrote it, it is gone now. Nothing to remove.
          unchanged  byte-for-byte what we left. A verbatim restore of the
                     pre-install copy is provably a perfect undo.
          changed    somebody edited it after us. Surgical removal, preserve
                     their edits, and name the backup rather than apply it.

        `unchanged` is the only state that may ever authorise writing an old
        copy over a live config file, and it is deliberately the narrowest: any
        doubt at all -- no record, no recorded checksum, an unreadable file --
        lands in `unknown` and takes the safe branch.
        """
        entry = self.entry(path, kind)
        out: Dict[str, Any] = {"state": "unknown", "entry": entry,
                               "path": str(path), "now": None, "wrote": None}
        if entry is None:
            return out
        out["wrote"] = entry.get("wrote")

        if entry.get("kind") == "symlink" or entry.get("target"):
            # A link has no bytes worth comparing; its identity is where it
            # points. A link that now points somewhere else is somebody else's.
            now = _link_target(path)
            out["now"] = now
            if now is None:
                out["state"] = "missing"
            elif entry.get("target") and _key(now) == _key(entry["target"]):
                out["state"] = "unchanged"
            elif entry.get("target"):
                out["state"] = "changed"
            return out

        now = digest(path)
        out["now"] = now
        if now is None:
            try:
                out["state"] = "unknown" if Path(path).exists() else "missing"
            except Exception:
                out["state"] = "unknown"
            return out
        wrote = entry.get("wrote")
        if not isinstance(wrote, str) or not wrote:
            return out            # we touched it but never recorded what we left
        out["state"] = "unchanged" if now == wrote else "changed"
        return out

    # -- recording -------------------------------------------------------

    def record(self, path: Any, *, kind: str, action: str,
               before: Optional[str] = None, wrote: Optional[str] = None,
               backup: Optional[Any] = None, scope: Optional[str] = None,
               target: Optional[Any] = None,
               baseline: Optional[Any] = None) -> Dict[str, Any]:
        """Add or refresh the row for one file. Returns the row.

        One row per (path, kind); a re-install updates it rather than appending
        a second. Two fields are write-once and that is the load-bearing detail:

        `before` is the checksum from the FIRST time this tool ever touched the
        file -- the genuinely pre-install state. On an upgrade the file already
        contains our hooks, so overwriting `before` would quietly redefine "the
        original" as "the previous install", and a later restore would put our
        own hooks back while calling itself a clean undo. `baseline` (the path
        to the byte-exact copy) is write-once for exactly the same reason.

        `before_last` carries the pre-write checksum of the MOST RECENT write,
        which is what a rollback of that write would need; keeping both costs
        one string and removes the ambiguity entirely.
        """
        row = self.entry(path, kind)
        if row is None:
            row = {"path": str(path), "kind": kind}
            self.entries.append(row)
            if before is not None:
                row["before"] = before
        elif before is not None and not row.get("before"):
            # First time we have a pre-touch checksum for a row that predates
            # this field. Fill it in; never replace one that is already there.
            row["before"] = before
        row["action"] = action
        if before is not None:
            row["before_last"] = before
        if wrote is not None:
            row["wrote"] = wrote
        if backup is not None:
            row["backup"] = str(backup)
        if baseline is not None and not row.get("baseline"):
            row["baseline"] = str(baseline)
        if scope is not None:
            row["scope"] = scope
        if target is not None:
            row["target"] = str(target)
        row["at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        return row

    def forget(self, path: Any, kind: Optional[str] = None) -> bool:
        """Drop the row(s) for a path we have just undone. True if any went."""
        want = _key(path)
        keep = [e for e in self.entries
                if not (_key(e.get("path")) == want
                        and (kind is None or e.get("kind") == kind))]
        changed = len(keep) != len(self.entries)
        self.entries = keep
        return changed

    # -- persistence -----------------------------------------------------

    def save(self) -> bool:
        """Write the manifest. Best effort, and that is on purpose.

        This is bookkeeping ABOUT an install, not part of one. A state directory
        that cannot be written is worth a quieter failure than aborting a write
        that already succeeded -- the uninstall path degrades to `unknown` and
        does the conservative thing, which is what it does on a fresh machine
        anyway.

        An empty manifest deletes itself rather than persisting as `[]`: a file
        recording nothing is litter that outlives the uninstall that emptied it.
        """
        try:
            if not self.entries:
                if self.path.exists():
                    self.path.unlink()
                return True
            self.path.parent.mkdir(parents=True, exist_ok=True)
            payload = {"version": SCHEMA_VERSION, "entries": self.entries}
            text = json.dumps(payload, indent=2, ensure_ascii=False) + "\n"
            tmp = self.path.with_name(
                "%s.%d.%d.tmp" % (self.path.name, os.getpid(), next(_TMP_SEQ)))
            try:
                with open(tmp, "w", encoding="utf-8", newline="\n") as handle:
                    handle.write(text)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(str(tmp), str(self.path))
            except BaseException:
                try:
                    tmp.unlink()
                except OSError:
                    pass
                raise
            return True
        except Exception:
            return False

    def __len__(self) -> int:
        return len(self.entries)
