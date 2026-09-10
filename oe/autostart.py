"""Install the opt-in shell one-liner that starts the supervisor at login.

WHY this module is its own file, and this careful:

The line it manages lives in ~/.zshrc -- tens of KB of the user's real shell
config, sourced by every terminal they open. A syntax error there is not a bug
reporting tool, it is a broken machine. So every write goes through the same
four gates:

  1. a numbered backup (~/.zshrc.overwatch-enforcer-bak-N) that is read back and
     compared BYTE FOR BYTE against the original before the original is touched;
  2. a delimited block, so removal is an exact cut and the rest of the file is
     never rewritten;
  3. `zsh -n` on the candidate text, so a file that would not parse is never
     put in place;
  4. a unique temp file + os.replace, so a reader mid-write sees the old file
     or the new one and never a half of either.

The line itself is built to be invisible: one `if`, three cheap builtin tests,
and a subshell that backgrounds the ensure call. The subshell is load-bearing --
`cmd &` at the top level of an interactive zsh prints a "[1] 12345" job notice,
inside `( ... & )` it does not.
"""

from __future__ import annotations

import hashlib
import itertools
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from . import paths

__all__ = ["BEGIN_MARKER", "END_MARKER", "default_rc", "rc_candidates",
           "assert_inside_home",
           "detect_shell", "shell_supported", "SUPPORTED_SHELLS",
           "guarded_line", "block_text", "block_target", "find_blocks", "install",
           "remove", "status",
           # The delimited-block engine, exported so that the OTHER managed
           # block this tool writes -- the PATH export in install.py --
           # gets these same four gates rather than a hand-rolled copy. A copy
           # would have to re-derive ZDOTDIR and bash-on-macOS, and would be
           # wrong for somebody. See edit_block().
           "find_blocks_of", "splice_block", "cut_blocks", "edit_block",
           "make_backup", "syntax_ok"]

BEGIN_MARKER = "# >>> claude overwatch-enforcer autostart >>>"
END_MARKER = "# <<< claude overwatch-enforcer autostart <<<"

# The markers this tool wrote under its previous name (usage-meter / `um`).
# Recognised, never written, so that an rc carrying the old block is migrated by
# the ordinary commands rather than by hand: --install rewrites it in place to
# the current block, --remove cuts it out, --status sees it. Without this the
# rename would strand a dead block in the user's shell config -- harmless,
# because its `-x .../bin/um` guard fails the moment the old install root is
# gone, but permanent and invisible.
LEGACY_MARKERS: List[Tuple[str, str]] = [
    ("# >>> claude usage-meter autostart >>>",
     "# <<< claude usage-meter autostart <<<"),
]

# ~/.zshrc.overwatch-enforcer-bak-<counter>. A counter rather than a timestamp so a
# second install never silently overwrites the pristine copy taken by the first.
BACKUP_SUFFIX = ".overwatch-enforcer-bak-"

# The escape hatch, named here so the CLI and the README quote the same string.
DISABLE_ENV = "OE_NO_AUTOSTART"

_TMP_SEQ = itertools.count()


def detect_shell() -> str:
    """'zsh' | 'bash' | '<other>' -- the LOGIN shell, from $SHELL.

    $SHELL is the login shell, which is the one that will source the rc file we
    write; the shell this Python happens to have been spawned from is not.
    macOS has defaulted to zsh since Catalina and most Linux distributions to
    bash, so both must be first class rather than one being the assumption.
    """
    try:
        name = os.path.basename(str(os.environ.get("SHELL") or "")).strip()
    except Exception:
        name = ""
    if name.startswith("-"):  # a login shell can be argv[0]-prefixed
        name = name[1:]
    if not name:
        # No $SHELL (cron, a launchd job, a container): use the platform
        # default rather than assuming zsh everywhere.
        return "zsh" if sys.platform == "darwin" else "bash"
    return name


def rc_candidates(shell: Optional[str] = None) -> List[Path]:
    """Every rc file that shell would source, best first.

    bash is the awkward one, and the reason this returns a list rather than a
    name: an interactive NON-login bash reads ~/.bashrc, but on macOS every
    Terminal window is a LOGIN shell, which reads ~/.bash_profile and NOT
    ~/.bashrc unless the user's own .bash_profile sources it. Writing to
    .bashrc on macOS installs a block that never runs.
    """
    shell = shell or detect_shell()
    try:
        home = Path.home()
    except Exception:  # pragma: no cover - no HOME and no passwd entry
        home = Path(os.path.expanduser("~"))
    if shell == "zsh":
        # ZDOTDIR relocates the whole zsh dotfile set; honouring it is the
        # difference between "installed" and "installed somewhere unread".
        zdotdir = os.environ.get("ZDOTDIR")
        base = Path(zdotdir).expanduser() if zdotdir else home
        return [base / ".zshrc"]
    if shell == "bash":
        if sys.platform == "darwin":
            return [home / ".bash_profile", home / ".bashrc"]
        return [home / ".bashrc", home / ".bash_profile"]
    if shell in ("sh", "dash", "ksh"):
        return [home / ".profile"]
    # An unsupported shell (fish, csh, nu, ...): the block is POSIX/bash/zsh
    # syntax and would not parse there. Name the file we WOULD have used so the
    # caller can say so out loud rather than silently writing something broken.
    return [home / (".%src" % shell)]


def _home() -> Path:
    try:
        return Path.home()
    except Exception:  # pragma: no cover - no HOME and no passwd entry
        return Path(os.path.expanduser("~"))


def assert_inside_home(rc: Path) -> None:
    """Refuse to edit an rc file outside the home directory we are running as.

    Not paranoia: zsh's ZDOTDIR is read from the ambient environment, so a
    process launched with HOME pointed at a scratch directory -- a test, a
    container build, a `sudo -H` that did not take -- still resolves
    default_rc() to the REAL user's ~/.zshrc and edits their shell config. The
    two variables disagreeing is always a mistake; --rc is the way to say you
    meant it.
    """
    home = _home()
    try:
        rc.resolve().relative_to(home.resolve())
        return
    except Exception:
        pass
    raise RuntimeError(
        f"{rc} is outside HOME ({home}); refusing to edit it. "
        "If that is really the file you want, name it with --rc.")


def default_rc(shell: Optional[str] = None) -> Path:
    """The rc this module manages: the first candidate that exists, else the
    platform-correct default for that shell."""
    candidates = rc_candidates(shell)
    for candidate in candidates:
        try:
            if candidate.exists():
                return candidate
        except Exception:
            continue
    return candidates[0]


# The shells the emitted block is valid in AND that we know how to syntax-check
# with `-n`. Anything else is refused rather than half-written.
SUPPORTED_SHELLS: Tuple[str, ...] = ("zsh", "bash", "sh", "dash", "ksh")


def shell_supported(shell: Optional[str] = None) -> bool:
    return (shell or detect_shell()) in SUPPORTED_SHELLS


def oe_bin() -> Path:
    return paths.INSTALL_ROOT / "bin" / "oe"


def guarded_line(binary: Optional[Path] = None) -> str:
    """The single line the block installs.

    Every clause earns its place:

    * `if ...; then ...; fi` rather than `A && B` so that a false guard cannot
      trip `set -e` and cannot leave a non-zero $? behind -- an `if` condition
      is exempt from errexit, and an `if` with no else returns 0.
    * `${VAR-}` (not `$VAR`) so `set -u` does not abort on an unset variable.
    * `-x <oe>` covers both "the install dir is gone" and "it is not runnable",
      in one stat.
    * `command -v python3` because the binary is a python3 script: without the
      interpreter the exec would fail and, more to the point, print.
    * `( ... & )` backgrounds inside a subshell: fully detached from the shell's
      job table, so zsh prints no job notice and the shell never waits.
    * `>/dev/null 2>&1 </dev/null` so nothing can reach the terminal and the
      child cannot ever block on stdin.
    """
    # Shell-quoted, because the install directory can contain a space --
    # '~/Library/Application Support/...' on macOS, 'My Tools' anywhere -- and
    # an unquoted path there turns `[ -x A B ]` into a syntax error in the rc
    # file that every terminal sources. shlex.quote leaves an ordinary path
    # untouched, so the common line is unchanged.
    import shlex
    target = shlex.quote(str(binary or oe_bin()))
    return (
        f'if [ -z "${{{DISABLE_ENV}-}}" ] && [ -x {target} ] && '
        'command -v python3 >/dev/null 2>&1; then '
        f'( {target} supervise --ensure >/dev/null 2>&1 </dev/null & ) ; fi'
    )


def block_text(binary: Optional[Path] = None) -> str:
    """The complete block, newline-terminated, markers included."""
    return (
        f"{BEGIN_MARKER}\n"
        f"# Starts the Overwatch Enforcer supervisor once per shell, detached and silent."
        f" Disable with: export {DISABLE_ENV}=1\n"
        f"{guarded_line(binary)}\n"
        f"{END_MARKER}\n"
    )


# ---------------------------------------------------------------------------
# block location
# ---------------------------------------------------------------------------

_RE_CACHE: Dict[Tuple[str, str], "re.Pattern[str]"] = {}


def _block_re(begin: str, end: str) -> "re.Pattern[str]":
    """The pattern matching one delimited block, memoised.

    Memoised because the marker pair is an ARGUMENT rather than a module
    constant: status() is called from the statusline path, and recompiling two
    regexes on every call to answer a question about a large rc file is a cost
    with nothing to show for it.
    """
    key = (begin, end)
    pattern = _RE_CACHE.get(key)
    if pattern is None:
        pattern = re.compile(
            r"^[ \t]*" + re.escape(begin) + r"[ \t]*$.*?^[ \t]*"
            + re.escape(end) + r"[ \t]*$\n?",
            re.MULTILINE | re.DOTALL,
        )
        _RE_CACHE[key] = pattern
    return pattern


def find_blocks_of(text: str, markers: List[Tuple[str, str]]) -> List[Tuple[int, int]]:
    """(start, end) character spans of every block delimited by `markers`.

    Plural on purpose: an install must be able to repair a file that somehow
    ended up with two copies, and a removal must take all of them out.

    Sorted by position and de-overlapped, because splice_block() and
    cut_blocks() walk the spans in order and slice between them: an unsorted or
    overlapping list would corrupt the rc rather than edit it.

    Marker-agnostic so that a second managed block -- the PATH export -- reuses
    this arithmetic instead of growing a second copy of it that would drift.
    """
    spans: List[Tuple[int, int]] = []
    for begin, end in markers:
        for match in _block_re(begin, end).finditer(text or ""):
            spans.append((match.start(), match.end()))
    spans.sort()
    out: List[Tuple[int, int]] = []
    for start, end in spans:
        if out and start < out[-1][1]:   # nested/overlapping: keep the first
            continue
        out.append((start, end))
    return out


def find_blocks(text: str) -> List[Tuple[int, int]]:
    """Every AUTOSTART block in `text`, ours and the ones our previous name
    wrote. Recognising the old markers is what lets one `--install` migrate a
    renamed install instead of appending a second block beside the dead one."""
    return find_blocks_of(text, [(BEGIN_MARKER, END_MARKER), *LEGACY_MARKERS])


def splice_block(text: str, block: str, spans: List[Tuple[int, int]]) -> str:
    """`text` with `block` in it exactly once, however many copies it had.

    The three shapes, and why each is spelled out rather than folded together:

    * blocks already present -- the FIRST is replaced in place and every
      duplicate is dropped, so the file can never accumulate copies however
      often this runs, and the block keeps the position the user is used to.
    * an EMPTY file -- the block and nothing else. A leading blank line here
      would survive removal (there is no preceding line for cut_blocks() to
      take it back from) and the round trip would not be byte-identical.
    * anything else -- one blank line, then the block. cut_blocks() takes
      exactly that blank line back.

    A file with no trailing newline also needs its last line terminated, and
    THAT newline is not recoverable; see cut_blocks().
    """
    if spans:
        pieces: List[str] = []
        cursor = 0
        for index, (start, end) in enumerate(spans):
            pieces.append(text[cursor:start])
            if index == 0:
                pieces.append(block)
            cursor = end
        pieces.append(text[cursor:])
        return "".join(pieces)
    if not text:
        return block
    separator = "" if text.endswith("\n") else "\n"
    return text + separator + "\n" + block


def cut_blocks(text: str, spans: List[Tuple[int, int]]) -> str:
    """`text` with those spans removed, leaving the rest byte-identical.

    The cut spans the BEGIN line through the END line and its newline -- exactly
    what splice_block() inserted -- plus the one blank line it put in front, so
    a file that had a block appended comes back to its original bytes.

    ONE byte is not recoverable: a file that did not end with a newline had one
    added, because without it the BEGIN marker would have been glued onto the
    user's last line. Removal cannot tell that newline from a real one, so such
    a file comes back with a trailing newline it did not have. Every other shape
    -- including the empty file -- round-trips exactly.
    """
    pieces: List[str] = []
    cursor = 0
    for start, end in spans:
        head = text[cursor:start]
        if head.endswith("\n\n"):
            head = head[:-1]
        pieces.append(head)
        cursor = end
    pieces.append(text[cursor:])
    return "".join(pieces)


def block_target(text: str) -> Optional[Path]:
    """The binary an INSTALLED block guards -- which is not necessarily ours.

    Cloning the tree to a different directory leaves the previous block behind,
    and its `-x <old>/bin/oe` guard then fails on every shell: the supervisor
    simply never starts and nothing anywhere says why. Reading the path back
    out of the block is what lets a caller name the stale checkout rather than
    report a bare "out of date".

    shlex rather than a regex, because guarded_line() shell-quotes the path and
    an install directory containing a space would defeat any pattern that
    stopped at whitespace.
    """
    import shlex
    for line in (text or "").splitlines():
        if not line.strip().startswith("if "):
            continue
        try:
            parts = shlex.split(line)
        except Exception:
            continue
        for index, part in enumerate(parts):
            if part != "-x" or index + 1 >= len(parts):
                continue
            candidate = Path(parts[index + 1])
            # Absolute or it is not a path: `[ -x ]` in a hand-mangled block
            # would otherwise be read as a binary called "]", and a caller
            # would go on to name that in a warning.
            if candidate.is_absolute():
                return candidate
    return None


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="surrogateescape")


def _digest(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


def file_digest(path: Path) -> Optional[str]:
    try:
        return _digest(path.read_bytes())
    except Exception:
        return None


# ---------------------------------------------------------------------------
# backup
# ---------------------------------------------------------------------------


def backup_paths(rc: Path) -> List[Path]:
    """Existing numbered backups of `rc`, oldest counter first."""
    prefix = rc.name + BACKUP_SUFFIX
    found: List[Tuple[int, Path]] = []
    try:
        for entry in rc.parent.iterdir():
            if not entry.name.startswith(prefix):
                continue
            tail = entry.name[len(prefix):]
            if tail.isdigit():
                found.append((int(tail), entry))
    except Exception:
        return []
    found.sort(key=lambda item: item[0])
    return [item[1] for item in found]


def _next_backup(rc: Path) -> Path:
    used = {int(p.name.rsplit("-", 1)[-1]) for p in backup_paths(rc)}
    counter = 1
    while counter in used:
        counter += 1
    return rc.with_name(rc.name + BACKUP_SUFFIX + str(counter))


def make_backup(rc: Path) -> Path:
    """Copy `rc` aside and PROVE the copy is byte-identical before returning.

    shutil.copy2 reporting success is not proof: a full disk, a truncated write
    or a copy onto a different filesystem can all leave a short file. The
    original is not touched unless the bytes read back match the bytes read in.
    """
    original = rc.read_bytes()
    target = _next_backup(rc)
    shutil.copy2(str(rc), str(target))
    copied = target.read_bytes()
    if copied != original:
        raise RuntimeError(
            f"backup {target} is not byte-identical to {rc} "
            f"({len(copied)} vs {len(original)} bytes); refusing to edit")
    return target


# ---------------------------------------------------------------------------
# safe write
# ---------------------------------------------------------------------------


def _checker_for(rc: Path) -> Optional[str]:
    """Which shell should parse this rc file.

    The file's own NAME is the better evidence than $SHELL: `--rc ~/.bashrc`
    must be checked by bash even when the user's login shell is zsh, because
    bash is what will source it. $SHELL only decides the ambiguous cases
    (.profile, a rehearsal copy in a temp dir).
    """
    name = rc.name.lower()
    if "zsh" in name:
        return "zsh"
    if "bash" in name:
        return "bash"
    shell = detect_shell()
    if shell in SUPPORTED_SHELLS:
        return shell
    return None


def syntax_ok(text: str, rc: Path) -> Optional[bool]:
    """Does the shell that will source this file parse it? None when it cannot
    be asked (that shell is not installed, or is one we do not check).

    `<shell> -n` parses without executing, which is the only cheap way to know
    the file we are about to install will not break every terminal the user
    opens. Verifying AFTER the fact would be too late. The checker is chosen
    from the rc file's name, so a bash rc is checked by bash even on a zsh
    machine -- bash and zsh disagree about enough syntax that checking with the
    wrong one is worth little.
    """
    checker = _checker_for(rc)
    if not checker or not shutil.which(checker):
        return None
    probe = rc.with_name(f"{rc.name}.oe-syntax.{os.getpid()}.{next(_TMP_SEQ)}.tmp")
    try:
        probe.write_text(text, encoding="utf-8", errors="surrogateescape")
        result = subprocess.run([checker, "-n", str(probe)],
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                timeout=20)
        return result.returncode == 0
    except Exception:
        return None
    finally:
        try:
            probe.unlink()
        except OSError:
            pass


def _replace_file(path: Path, text: str) -> None:
    """Atomic replace that preserves the original file mode AND any symlink.

    paths.atomic_write() would do the rename, but it creates the temp with the
    default umask; a .zshrc that came back 0600 (or 0666) after an edit would be
    a surprise the user did not ask for.

    The realpath() matters more than it looks: a dotfiles repo checkout makes
    ~/.zshrc a symlink into ~/dotfiles, and os.replace() onto the LINK deletes
    the link and drops a plain file in its place -- the repo keeps the old
    content, the edit is orphaned, and the next `stow`/`git checkout` silently
    undoes it. Writing through the link edits the file the user actually keeps.
    The temp is made beside the resolved target so the rename stays on one
    filesystem; if it cannot be, os.replace raises and the rc is left alone.
    """
    try:
        path = Path(os.path.realpath(str(path)))
    except OSError:
        pass
    try:
        mode = path.stat().st_mode & 0o7777
    except OSError:
        mode = 0o644
    tmp = path.with_name(f"{path.name}.oe.{os.getpid()}.{next(_TMP_SEQ)}.tmp")
    try:
        with open(tmp, "w", encoding="utf-8", errors="surrogateescape",
                  newline="\n") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        try:
            tmp.unlink()
        except OSError:
            pass
        raise


# ---------------------------------------------------------------------------
# public operations
# ---------------------------------------------------------------------------


def status(rc: Optional[Path] = None) -> Dict[str, Any]:
    """What is installed right now. Never raises."""
    rc = Path(rc or default_rc())
    expected = block_text()
    out: Dict[str, Any] = {
        "rc": str(rc),
        "exists": rc.is_file(),
        "installed": False,
        "blocks": 0,
        "current": False,
        "line": guarded_line(),
        "disable_env": DISABLE_ENV,
        "disabled_now": bool(os.environ.get(DISABLE_ENV)),
        "oe": str(oe_bin()),
        "oe_executable": os.access(str(oe_bin()), os.X_OK),
        "backups": [str(p) for p in backup_paths(rc)],
        "md5": file_digest(rc),
        "supervisor_pid": None,
        "supervisor_running": False,
    }
    try:
        text = _read(rc) if rc.is_file() else ""
    except Exception:
        text = ""
    spans = find_blocks(text)
    out["blocks"] = len(spans)
    out["installed"] = bool(spans)
    if spans:
        start, end = spans[0]
        out["current"] = text[start:end] == expected
        out["block"] = text[start:end]
    try:
        from . import watcher as watcher_mod
        pid = watcher_mod.supervisor_running()
        out["supervisor_pid"] = pid
        out["supervisor_running"] = bool(pid)
    except Exception:
        pass
    return out


def install(rc: Optional[Path] = None, *, backup: bool = True) -> Dict[str, Any]:
    """Append (or refresh in place) the managed block. Idempotent.

    Returns a dict with "changed", "action", "backup", "md5_before"/"md5_after".
    Raises only when it refuses to write: a failed backup verification or a
    candidate zsh will not parse.
    """
    explicit = rc is not None
    rc = Path(rc or default_rc())
    if not explicit:
        assert_inside_home(rc)
    block = block_text()
    if not rc.exists():
        # Creating a shell rc that did not exist is a bigger decision than this
        # command is allowed to make on the user's behalf.
        raise FileNotFoundError(f"{rc} does not exist")
    before = rc.read_bytes()
    text = before.decode("utf-8", errors="surrogateescape")
    spans = find_blocks(text)

    if spans and len(spans) == 1 and text[spans[0][0]:spans[0][1]] == block:
        return {"changed": False, "action": "already-installed", "rc": str(rc),
                "backup": None, "md5_before": _digest(before),
                "md5_after": _digest(before), "blocks": 1}

    # One implementation of the splice arithmetic, shared with edit_block(): a
    # second copy here is a second place for the blank-line bookkeeping that
    # makes remove() byte-exact to drift out of agreement.
    candidate = splice_block(text, block, spans)
    action = "updated" if spans else "installed"

    parsed = syntax_ok(candidate, rc)
    if parsed is False:
        raise RuntimeError(
            f"{_checker_for(rc) or 'the shell'} -n rejected the result; "
            f"{rc} left untouched")

    backup_path = make_backup(rc) if backup else None
    _replace_file(rc, candidate)
    after = rc.read_bytes()
    return {"changed": True, "action": action, "rc": str(rc),
            "backup": str(backup_path) if backup_path else None,
            "md5_before": _digest(before), "md5_after": _digest(after),
            "blocks": len(find_blocks(after.decode("utf-8", errors="surrogateescape"))),
            "syntax_checked": parsed is True}


def remove(rc: Optional[Path] = None, *, backup: bool = True) -> Dict[str, Any]:
    """Cut the managed block out, leaving the rest of the file byte-identical.

    The cut spans the BEGIN line through the END line and its newline -- exactly
    what install() inserted -- plus the one blank line install() put in front of
    it, so a file that had the block appended comes back to its original bytes.

    ONE byte is not recoverable: an rc that did not end with a newline had one
    added by install(), because without it the BEGIN marker would have been
    glued onto the user's last line. Removal cannot tell that newline from a
    real one, so such a file comes back with a trailing newline it did not have.
    Every other shape -- including the empty file -- round-trips exactly.
    """
    explicit = rc is not None
    rc = Path(rc or default_rc())
    if not explicit:
        assert_inside_home(rc)
    if not rc.exists():
        return {"changed": False, "action": "no-rc", "rc": str(rc), "backup": None}
    before = rc.read_bytes()
    text = before.decode("utf-8", errors="surrogateescape")
    spans = find_blocks(text)
    if not spans:
        return {"changed": False, "action": "not-installed", "rc": str(rc),
                "backup": None, "md5_before": _digest(before),
                "md5_after": _digest(before)}

    # install() writes "\n" + block after a newline-terminated file, so the
    # blank line immediately above each block is ours to take back. Shared with
    # edit_block() for the same reason install() shares splice_block().
    candidate = cut_blocks(text, spans)

    parsed = syntax_ok(candidate, rc)
    if parsed is False:
        raise RuntimeError(
            f"{_checker_for(rc) or 'the shell'} -n rejected the result; "
            f"{rc} left untouched")

    backup_path = make_backup(rc) if backup else None
    _replace_file(rc, candidate)
    after = rc.read_bytes()
    return {"changed": True, "action": "removed", "rc": str(rc),
            "backup": str(backup_path) if backup_path else None,
            "md5_before": _digest(before), "md5_after": _digest(after),
            "blocks": len(find_blocks(after.decode("utf-8", errors="surrogateescape"))),
            "syntax_checked": parsed is True}


def edit_block(rc: Path, *, begin: str, end: str, block: Optional[str] = None,
               remove_only: bool = False, backup: bool = True,
               dry_run: bool = False) -> Dict[str, Any]:
    """Put `block` between `begin`/`end` in `rc`, or cut it out. Idempotent.

    This is install()/remove() with the marker pair and the payload as
    ARGUMENTS, so the second block this tool manages -- the PATH export that
    install.py --path-fix writes -- runs through this module's four gates
    instead of a hand-rolled snippet. That matters more than the code it saves:
    a snippet in the documentation cannot know about $ZDOTDIR, and cannot know
    that every Terminal window on macOS is a LOGIN bash that reads
    .bash_profile and never .bashrc. Somebody following it would install a line
    that never runs and have nothing to tell them so.

    `dry_run=True` computes the whole answer -- including the syntax check on
    the candidate text, which is the expensive and interesting half -- and
    writes nothing. That is what lets the caller print exactly the line it would
    add and still be a dry run.

    Returns a dict: changed, action (installed|updated|removed|already-installed|
    not-installed|no-rc), rc, backup, md5_before, md5_after, blocks,
    syntax_checked, candidate. Raises only when it REFUSES to write: a backup
    that did not verify, or a candidate the shell will not parse.
    """
    rc = Path(rc)
    markers = [(begin, end)]
    if not rc.exists():
        # Creating somebody's shell rc from nothing is a bigger decision than
        # this function is allowed to make; the caller says so in its own words.
        return {"changed": False, "action": "no-rc", "rc": str(rc),
                "backup": None, "candidate": None, "blocks": 0}
    before = rc.read_bytes()
    text = before.decode("utf-8", errors="surrogateescape")
    spans = find_blocks_of(text, markers)

    if remove_only:
        if not spans:
            return {"changed": False, "action": "not-installed", "rc": str(rc),
                    "backup": None, "md5_before": _digest(before),
                    "md5_after": _digest(before), "candidate": None, "blocks": 0}
        candidate = cut_blocks(text, spans)
        action = "removed"
    else:
        if block is None:
            raise ValueError("edit_block() needs a block unless remove_only")
        if len(spans) == 1 and text[spans[0][0]:spans[0][1]] == block:
            return {"changed": False, "action": "already-installed", "rc": str(rc),
                    "backup": None, "md5_before": _digest(before),
                    "md5_after": _digest(before), "candidate": None, "blocks": 1}
        candidate = splice_block(text, block, spans)
        action = "updated" if spans else "installed"

    parsed = syntax_ok(candidate, rc)
    if parsed is False:
        raise RuntimeError(
            f"{_checker_for(rc) or 'the shell'} -n rejected the result; "
            f"{rc} left untouched")
    if dry_run:
        return {"changed": False, "action": action, "rc": str(rc), "backup": None,
                "md5_before": _digest(before), "md5_after": None,
                "candidate": candidate, "dry_run": True,
                "blocks": len(find_blocks_of(candidate, markers)),
                "syntax_checked": parsed is True}

    backup_path = make_backup(rc) if backup else None
    _replace_file(rc, candidate)
    after = rc.read_bytes()
    # Re-check what actually landed rather than what we meant to land: the
    # candidate parsed, but only the file on disk is the file every terminal
    # will source, and proving THAT is the point of the exercise.
    settled = syntax_ok(after.decode("utf-8", errors="surrogateescape"), rc)
    return {"changed": True, "action": action, "rc": str(rc),
            "backup": str(backup_path) if backup_path else None,
            "md5_before": _digest(before), "md5_after": _digest(after),
            "candidate": candidate,
            "blocks": len(find_blocks_of(
                after.decode("utf-8", errors="surrogateescape"), markers)),
            "syntax_checked": parsed is True, "syntax_after": settled}
