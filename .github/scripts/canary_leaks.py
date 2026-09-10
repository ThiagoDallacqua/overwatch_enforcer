#!/usr/bin/env python3
"""Try to defeat the leak gate. A gate nobody has attacked is not a gate.

Five rounds of sweeping this tree failed, and the last verifier found why: a
planted canary carrying a dollar amount, a corpus byte total, an employer name
and a private filename passed `leak_gate.py --require-git` AND `oe package`
GREEN, with the archive written. Both gates were path-based. A green result was
never evidence.

So this script is the evidence. It works in BOTH directions:

  MUST FAIL -- one forbidden shape is planted into a COPY of the tree and the
    gate must report it. If the gate stays quiet the canary FAILS, and the
    output names the shape that got through.
  MUST PASS -- a benign string is planted into a copy and the gate must NOT
    react to it. Anthropic's published list prices, version numbers, HTTP
    status codes, a units-conversion table, a SQL limit, an ANSI colour code, a
    regex character class, a timeout in seconds. A rule that eats these is a
    rule nobody will keep.

Every case is measured as a DELTA against a baseline run of the untouched copy,
so the suite is meaningful while the tree still has findings in it. Two
absolute assertions sit alongside the deltas: the gate must pass outright on
the real tree, and `oe package` must refuse to write an archive when a canary
is planted.

The `--require-git` cases drive the gate against a STUB `git` on PATH. That is
deliberate: `git init` is not run anywhere in this repository's test path, and
a stub pins the exact failure the flag exists to prevent -- a checkout sitting
inside somebody else's repository, where real git exits 0 and answers for that
repository instead of this one.

  python3 .github/scripts/canary_leaks.py          # everything
  python3 .github/scripts/canary_leaks.py -v       # print each gate finding
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

#: Where a planted string goes. A shipped .py file inside the allowlist, so it
#: is scanned by every tier. Its own content is irrelevant: the canary is
#: appended as a module-level comment block, which is where this class lives.
CANARY_FILE = "oe/version.py"

#: Invented values, all of them. A canary that carried a REAL figure would be
#: the leak it is testing for, so every number below is a repeated digit or a
#: round value no measurement lands on, and every name is fictional.
EMPLOYER = "Initech"
PRIVATE_BASENAME = "quarterly_ingest.ts"

# THE SHAPE CANARIES ARE ASSEMBLED, NOT WRITTEN OUT. This file is itself a
# shipped file that the gate scans, so a literal uuid, home path or issue key
# in it would be a permanent finding against the suite that plants it -- the
# permanent finding against the suite that plants it. Each half
# below is inert on its own: `/home/` has no username after it, `INIT-` has no
# number after it, and neither half of the uuid is uuid-shaped.
_CANARY_UUID = "7c4e1b02-9a3f-4d55" + "-b8e1-06f2a9d4c317"
_CANARY_HOME = "/home/" + "rwilliams" + "/work"
_CANARY_KEY = "INIT" + "-" + "4821"


def _comment(*lines: str) -> str:
    return "\n\n" + "\n".join(f"# {line}" for line in lines) + "\n"


#: (name, what to append, which gate list it must land in, why it is forbidden)
MUST_FAIL = (
    ("money with a dollar sign",
     _comment("the whole run cost ${:,.2f} before lunch".format(412.90)),
     "content", "an amount measured on the author's spending"),
    ("money with no dollar sign",
     _comment("total spend for the week was {:,.2f} across both accounts"
              .format(512.40)),
     "content", "the bare-decimal shape a symbol-based rule cannot see"),
    ("a corpus byte total",
     _comment("read every transcript in one pass: {:,} files, {:,} MB"
              .format(777, 888)),
     "content", "the size of the author's private corpus"),
    ("a token count",
     _comment("the window carried {:,} tokens before the compact".format(11111111)),
     "content", "a token absolute measured on the author's sessions"),
    ("a request count",
     _comment("{:,} requests went through the main loop".format(22222)),
     "content", "a request absolute measured on the author's sessions"),
    ("a session count",
     _comment("averaged over the {} sessions this was built against".format(33)),
     "content", "how many sessions the author has"),
    ("a file size",
     _comment("this module is {:,} lines and nothing imports it lazily"
              .format(4444)),
     "content", "a file size measured on this machine"),
    ("a timing",
     _comment("the cold guard call measured {} ms on this machine".format(55.5)),
     "content", "a timing measured on this machine"),
    ("a percentage beside a rate",
     _comment("{}% of it was repeat, at ${}/1k that is real money"
              .format(77.7, 0.999)),
     "content", "a ratio and a rate that multiply back into an amount"),
    ("a real-looking session id",
     _comment(f"seen while debugging: {_CANARY_UUID}"),
     "shape", "a session uuid"),
    ("a ticket id",
     _comment(f"follow-up tracked as {_CANARY_KEY}"),
     "shape", "an issue key names a private tracker and project"),
    ("a home path",
     _comment(f"reproduced under {_CANARY_HOME} before the fix"),
     "shape", "an absolute home path names the user"),
    ("an employer name",
     _comment(f"{EMPLOYER} runs this on the build box every night"),
     "denylist", "a proper noun; only the local denylist can see it"),
    ("a private file basename",
     _comment(f"the pathological input was {PRIVATE_BASENAME}"),
     "denylist", "a private source filename; only the denylist can see it"),
    # The combined case: four different
    # classes in a single comment block in a single file.
    ("THE COMBINED CANARY (money + byte total + employer + private filename)",
     _comment("${:,.2f} of it was cache reads".format(412.90),
              "across {:,} files and {:,} MB of transcript".format(777, 888),
              f"{EMPLOYER} pays for this",
              f"worst offender was {PRIVATE_BASENAME}"),
     "content", "four classes in one comment block in one file"),
)

#: (name, what to append). None of these may change the gate's answer at all.
MUST_PASS = (
    ("Anthropic published list prices",
     _comment("Opus is $15.00 / Mtok in and $75.00 per Mtok out",
              "Haiku is $1.00 / Mtok in; see oe/pricing.py for the catalog")),
    ("version numbers",
     _comment("requires SQLite 3.43.0 or newer; 3.46.1 has the fix",
              "Python 3.10.4 is the floor and 3.13.2 is tested")),
    ("HTTP status codes",
     _comment("retry on 429 and 503; give up on 404 and 410")),
    ("byte sizes in a units-conversion table",
     _comment("1 KB is 1024 bytes, 1 MB is 1024 KB, 1 GB is 1024 MB")),
    ("a SQL limit",
     '\n\n_TOP = "SELECT rowid FROM docs ORDER BY rank LIMIT 5000"\n'),
    ("ANSI colour codes",
     '\n\n_ALT = "\\x1b[?1049h"\n_DIM = "\\x1b[38;5;244m"\n_OFF = "\\x1b[0m"\n'),
    ("a regex character class",
     '\n\n_KEY = r"[A-Z][A-Z0-9]{1,9}-[0-9]{1,6}"\n_HEX = r"[0-9a-f]{8}"\n'),
    ("timeouts in seconds",
     _comment("settings.json gives this hook 180s; SessionStart gets 15s",
              "a 5 s poll is affordable for hours")),
    ("a ratio carrying a finding with no absolute",
     _comment("a measured 40.4% false-block rate is why the rule was dropped")),
    ("a divisor",
     _comment("context cost is bytes / 4 tokens, written to cache once")),
)


# --- driving the gate -------------------------------------------------------


def copy_tree(dest: Path) -> Path:
    """A working copy of the tree: everything the gates read, nothing runtime."""
    ignore = shutil.ignore_patterns(
        "state", "reports", "__pycache__", ".git", "*.pyc", "*.tar.gz")
    shutil.copytree(ROOT, dest, ignore=ignore, symlinks=True)
    return dest


def run_gate(root: Path, extra=(), env_extra=None):
    """(returncode, parsed json or None, stderr) for one gate run."""
    env = dict(os.environ)
    env.pop("OE_LEAK_DENYLIST", None)
    if env_extra:
        env.update(env_extra)
    proc = subprocess.run(
        [sys.executable, str(root / ".github" / "scripts" / "leak_gate.py"),
         "--json", *extra],
        capture_output=True, text=True, env=env, timeout=600)
    try:
        return proc.returncode, json.loads(proc.stdout), proc.stderr
    except Exception:
        return proc.returncode, None, proc.stdout + proc.stderr


def finding_set(payload):
    """The gate's answer as a comparable set of (bucket, file, sample)."""
    out = set()
    for bucket in ("shape", "content", "denylist"):
        for hit in payload.get(bucket) or []:
            out.add((bucket, hit["file"],
                     hit.get("sample") or hit.get("term")))
    return out


class Report:
    def __init__(self, verbose: bool):
        self.rows = []
        self.verbose = verbose

    def add(self, ok: bool, name: str, detail: str = "") -> None:
        self.rows.append((ok, name, detail))
        mark = "PASS" if ok else "FAIL"
        print(f"  [{mark}] {name}" + (f"  -- {detail}" if detail else ""))

    @property
    def failures(self):
        return [row for row in self.rows if not row[0]]


def canary_round(report: Report, denylist_file: Path) -> None:
    """Plant one thing at a time into a fresh copy and read the gate's answer."""
    scratch = Path(tempfile.mkdtemp(prefix="oe-canary-"))
    try:
        copy = copy_tree(scratch / "tree")
        env = {"OE_LEAK_DENYLIST": str(denylist_file)}
        rc, base, err = run_gate(copy, env_extra=env)
        if base is None:
            report.add(False, "baseline gate run", f"gate produced no JSON: {err[:400]}")
            return
        baseline = finding_set(base)
        print(f"  (baseline: {len(baseline)} finding(s) on the untouched copy, "
              f"denylist tier {'ran' if base['denylist_ran'] else 'DID NOT RUN'})")
        if not base["denylist_ran"]:
            report.add(False, "denylist tier is reachable",
                       "the suite pointed $OE_LEAK_DENYLIST at a real file and "
                       "the gate still did not load it")

        target = copy / CANARY_FILE
        pristine = target.read_text(encoding="utf-8")

        for name, payload, bucket, why in MUST_FAIL:
            target.write_text(pristine + payload, encoding="utf-8")
            rc, out, err = run_gate(copy, env_extra=env)
            target.write_text(pristine, encoding="utf-8")
            if out is None:
                report.add(False, f"MUST FAIL: {name}", f"no JSON: {err[:200]}")
                continue
            new = finding_set(out) - baseline
            caught = [hit for hit in new if hit[0] == bucket]
            detail = why if not caught else ""
            if caught and rc == 0:
                caught, detail = [], "the gate listed it but still exited 0"
            report.add(bool(caught), f"MUST FAIL: {name}", detail)
            if report.verbose and new:
                for hit in sorted(new):
                    print(f"          caught: {hit}")

        for name, payload in MUST_PASS:
            target.write_text(pristine + payload, encoding="utf-8")
            rc, out, err = run_gate(copy, env_extra=env)
            target.write_text(pristine, encoding="utf-8")
            if out is None:
                report.add(False, f"MUST PASS: {name}", f"no JSON: {err[:200]}")
                continue
            new = finding_set(out) - baseline
            report.add(not new, f"MUST PASS: {name}",
                       "" if not new else f"tripped on {sorted(new)}")

        # `oe package` must refuse to write the archive, not merely complain.
        target.write_text(pristine + MUST_FAIL[-1][1], encoding="utf-8")
        try:
            sys.path.insert(0, str(copy))
            for mod in [m for m in list(sys.modules) if m == "oe" or m.startswith("oe.")]:
                del sys.modules[mod]
            os.environ["OE_LEAK_DENYLIST"] = str(denylist_file)
            from oe import package as package_mod  # noqa: E402
            out_path = scratch / "bundle.tar.gz"
            result = package_mod.build(root=copy, out=out_path)
            report.add(not result.ok and not out_path.exists(),
                       "MUST FAIL: `oe package` writes no archive for the "
                       "combined canary",
                       "" if not out_path.exists() else "AN ARCHIVE WAS WRITTEN")
        except Exception as exc:
            report.add(False, "MUST FAIL: `oe package` refuses the canary",
                       f"{type(exc).__name__}: {exc}")
        finally:
            target.write_text(pristine, encoding="utf-8")
            sys.path.remove(str(copy))
            for mod in [m for m in list(sys.modules) if m == "oe" or m.startswith("oe.")]:
                del sys.modules[mod]
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


# --- the --require-git trap -------------------------------------------------

_STUB = """#!/bin/sh
# A stand-in for git. $STUB_TOPLEVEL is what `rev-parse --show-toplevel`
# answers. $STUB_FILES is the ls-files answer, newline-separated here and
# translated to the NUL separators `-z` promises on the way out, because an
# environment variable cannot carry a NUL byte.
case "$*" in
  *rev-parse*--show-toplevel*) printf '%s\\n' "$STUB_TOPLEVEL"; exit 0 ;;
  *ls-files*)
    if [ -n "$STUB_FILES" ]; then
      printf '%s\\n' "$STUB_FILES" | tr '\\n' '\\000'
    fi
    exit 0 ;;
esac
exit 0
"""


def require_git_round(report: Report) -> None:
    """The exact trap --require-git exists to prevent, in both of its shapes."""
    scratch = Path(tempfile.mkdtemp(prefix="oe-canary-git-"))
    try:
        copy = copy_tree(scratch / "tree")
        stub_dir = scratch / "stub"
        stub_dir.mkdir()
        stub = stub_dir / "git"
        stub.write_text(_STUB, encoding="utf-8")
        stub.chmod(0o755)
        path = f"{stub_dir}{os.pathsep}{os.environ.get('PATH', '')}"

        def gate(toplevel: str, files: str, extra=()):
            env = dict(os.environ)
            env.update({"PATH": path, "STUB_TOPLEVEL": toplevel,
                        "STUB_FILES": files})
            env.pop("OE_LEAK_DENYLIST", None)
            return subprocess.run(
                [sys.executable,
                 str(copy / ".github" / "scripts" / "leak_gate.py"), *extra],
                capture_output=True, text=True, env=env, timeout=600)

        # 1. The checkout sits INSIDE another repository: git exits 0, answers
        #    for that repository, and lists nothing here.
        proc = gate(str(scratch), "", ("--require-git",))
        report.add(proc.returncode != 0,
                   "MUST FAIL: --require-git inside somebody else's repository",
                   "" if proc.returncode else
                   "exited 0 having asserted nothing -- the original bug")
        said_root = "git root" in proc.stdout or "NOT" in proc.stdout
        report.add(said_root,
                   "  ... and says WHY (the git root is not the install root)",
                   "" if said_root else f"message was: {proc.stdout[-300:]!r}")

        # 2. The git root IS this tree, but git reports zero files. A real
        #    checkout of this repository can never legitimately track nothing.
        proc = gate(str(copy), "", ("--require-git",))
        report.add(proc.returncode != 0,
                   "MUST FAIL: --require-git when git reports zero files",
                   "" if proc.returncode else "exited 0 on an empty file list")

        # 3. A well-formed answer gets past the guard and into the real checks:
        #    a forbidden tracked path must still be caught.
        proc = gate(str(copy), "README.md\nstate/accounts.json",
                    ("--require-git",))
        caught = "MUST NOT BE TRACKED" in proc.stdout
        report.add(caught,
                   "MUST FAIL: a forbidden path in a well-formed tracked list",
                   "" if caught else "hygiene tier did not fire")

        # 4. Without the flag, a non-checkout is allowed to scan the allowlist
        #    only -- it must SAY so rather than implying a git check ran.
        proc = gate(str(scratch), "")
        said = "scanning the allowlist only" in proc.stdout
        report.add(said, "MUST SAY: no flag, no git -- allowlist only",
                   "" if said else f"message was: {proc.stdout[:200]!r}")
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


# --- the real tree ----------------------------------------------------------


def real_tree_round(report: Report) -> None:
    rc, out, err = run_gate(ROOT)
    if out is None:
        report.add(False, "the real tree passes the gate", f"no JSON: {err[:300]}")
        return
    counts = {k: len(out.get(k) or []) for k in ("shape", "content", "denylist")}
    detail = "" if rc == 0 else (
        f"{counts['shape']} shape, {counts['content']} content, "
        f"{counts['denylist']} denylist finding(s) still in the tree; "
        f"{len(out.get('deferred') or [])} more deferred inside docs/ sample "
        f"blocks. Run the gate without --json to read them.")
    report.add(rc == 0, "the real tree passes the gate outright", detail)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="print every finding a canary produced")
    args = parser.parse_args()

    report = Report(args.verbose)
    scratch = Path(tempfile.mkdtemp(prefix="oe-canary-list-"))
    try:
        denylist = scratch / "leak-denylist.txt"
        denylist.write_text(
            "# invented terms, planted by the canary suite\n"
            f"{EMPLOYER}\n{PRIVATE_BASENAME}\n", encoding="utf-8")

        print("\n== planted canaries (a copy of the tree, one shape at a time) ==")
        canary_round(report, denylist)
        print("\n== the --require-git trap (a stub git on PATH) ==")
        require_git_round(report)
        print("\n== the real tree ==")
        real_tree_round(report)
    finally:
        shutil.rmtree(scratch, ignore_errors=True)

    total = len(report.rows)
    bad = report.failures
    print(f"\n{total - len(bad)}/{total} canary assertions passed")
    if bad:
        print("\nFAILED:")
        for _ok, name, detail in bad:
            print(f"  {name}" + (f"  -- {detail}" if detail else ""))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
