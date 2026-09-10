#!/usr/bin/env python3
"""The sweep. One command, one answer, and an honest account of what it missed.

Five rounds of sweeping this tree failed. The rounds were not lazy; they were
aimed at the wrong target. Each one asked "what leaks are in the tree right
now", fixed the instances on that list, and reported green -- and then the next
round found more, because:

  * FIXING WRITES NEW TEXT. The class lives in comments, and a fix round's own
    comments are new comments. A sweep that reads the tree and then edits the
    tree has invalidated its own result by the time it prints it.
  * A GREEN GATE IS EVIDENCE ABOUT ITS RULES, NOT ABOUT THE TREE. It was read
    as the second thing every time. A planted canary carrying money, a corpus
    byte total, an employer name and a private filename passed both gates green
    with the archive written.
  * THE CHECKS THEMSELVES WERE NEVER CHECKED. The ad-hoc half of every round
    was shell one-liners, and they were wrong repeatedly -- a whitespace-
    collapsing anchor check, an unquoted variable that never split into
    arguments, a substring match that ate its own fixtures, a scratch root that
    suppressed the exact migration under test. Each wrong answer cost a round.
  * FINDINGS ARRIVED AFTER DECISIONS. Long adversarial passes reported at the
    end, by which time the tree had moved and a result had already been
    announced.

So this file is aimed somewhere else. It does not ask what is in the tree. It
asks four questions, in this order, and prints every answer the moment it has
it:

  1. DO THE CHECKS WORK? Every tier plants a positive and must find it. A tier
     that has not been shown to fire is not evidence and is reported as such.
  2. IS ANYTHING FORBIDDEN PRESENT? The shape, content and denylist tiers of
     leak_gate.py, unchanged, plus the corpus tier below.
  3. DOES A SHIPPED FIGURE EQUAL A FIGURE THIS MACHINE MEASURED? Not "does it
     look measured" -- an exact comparison against local runtime state. See
     oe/corpus.py. This is the tier the earlier rounds did not have.
  4. WHAT COULD THIS RUN NOT SEE? Always printed, green or not, because the
     one failure every round shared was a green result being read as more than
     it was.

Streaming is a design requirement, not a convenience. Every finding goes to
stdout the instant it is known and is appended to the JSONL under --out, so a
long run can be watched rather than waited on.

  python3 .github/scripts/sweep.py                 # everything, stream
  python3 .github/scripts/sweep.py --since         # only what this round ADDED
  python3 .github/scripts/sweep.py --quick         # skip the surface tier
  python3 .github/scripts/sweep.py --json          # machine-readable summary
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from oe import corpus, package  # noqa: E402

BASELINE = ROOT / "state" / "sweep" / "baseline.json"

#: Commands that only read. Each is run for real and must exit 0 with no
#: traceback. Anything NOT on this list is `--help`-checked only, and the
#: blind-spot section names it -- a parser that imports is not a command that
#: works, and pretending otherwise is how a surface check lies.
READ_ONLY = (
    ("version", ["version"]),
    ("status --last", ["status", "--last", "--json"]),
    ("sessions", ["sessions"]),
    ("account", ["account"]),
    ("doctor", ["doctor"]),
    ("audit", ["audit"]),
    ("savings", ["savings"]),
    ("rereads", ["rereads"]),
    ("find", ["find", "atomic_write"]),
    ("deps", ["deps", "oe/paths.py"]),
    ("slice", ["slice", "oe/paths.py", "atomic_write"]),
    ("package", ["package", "--dir", "--out", "{scratch}/bundle"]),
    ("supervise --status", ["supervise", "--status"]),
    ("autostart --status", ["autostart", "--status"]),
    ("whois", ["whois", "session_01"]),
    ("repair", ["repair"]),
)

#: What no tier in this file looks for. Printed on EVERY run. An unlisted
#: blind spot is the failure mode this whole file exists to prevent, so this
#: tuple is part of the result, not documentation about it.
BLIND_SPOTS = (
    "a proper noun -- employer, client, product, person, private basename -- "
    "unless this machine has a local denylist naming it. There is no list in "
    "CI, so on a runner this is a human read.",
    "a figure this machine never wrote to local state: read off a terminal, "
    "held in a head, or measured somewhere else. The corpus tier compares "
    "against what is on disk and nothing more.",
    "a figure below five significant digits. `100`, `15.00` and `1.23` are "
    "everybody's numbers and matching them is a rule nobody keeps.",
    "a figure spelled in words, split across two lines, or transformed by "
    "anything but division by a small constant. Every rule here is line-local.",
    "whether an entry in PLACEHOLDERS, CONTENT_ALLOW or _UNIT_ANCHORS is "
    "correct. Each exemption is a permanent hole that only review closes.",
    "a file that BOTH the bundle allowlist and git miss. drift() compares the "
    "two against each other; a file in neither is invisible to both.",
    "whether a command that was only --help-checked actually works.",
)


class Sweep:
    """Runs the tiers and streams. Owns the exit code and the finding log."""

    def __init__(self, out: Path, verbose: bool) -> None:
        self.out = out
        self.verbose = verbose
        self.findings = []
        self.tiers = {}
        self.notes = []
        out.parent.mkdir(parents=True, exist_ok=True)
        self.handle = out.open("w", encoding="utf-8")

    def say(self, line: str) -> None:
        print(line, flush=True)

    def tier(self, name: str) -> None:
        self.say(f"\n── {name} " + "─" * max(0, 60 - len(name)))

    def finding(self, tier: str, severity: str, where: str, what: str,
                quiet_rows=None) -> None:
        """Print and persist one finding IMMEDIATELY. Nothing is batched.

        `quiet_rows` carries the individual hits behind a summarised finding.
        They go to the JSONL in full and never to the console, so collapsing a
        hundred rows into one line loses nothing that a later run can read.
        """
        row = {"tier": tier, "severity": severity, "where": where, "what": what}
        self.findings.append(row)
        mark = {"fatal": "!!", "warn": " !", "info": "  "}[severity]
        self.say(f"  {mark} {where}  {what}")
        self.handle.write(json.dumps(row, sort_keys=True) + "\n")
        for detail in quiet_rows or ():
            self.handle.write(json.dumps(
                {"tier": tier, "severity": "detail", **detail},
                sort_keys=True) + "\n")
        self.handle.flush()

    def result(self, name: str, ok: bool, detail: str) -> None:
        self.tiers[name] = {"ok": ok, "detail": detail}
        self.say(f"  {'PASS' if ok else 'FAIL'}  {name}: {detail}")

    def close(self) -> None:
        self.handle.close()

    @property
    def fatal(self):
        return [f for f in self.findings if f["severity"] == "fatal"]


def tier_gate(sweep: Sweep) -> None:
    """Tiers 1-4, delegated to leak_gate.py unchanged. It self-tests itself."""
    sweep.tier("tiers 1-4  hygiene / shape / content / denylist")
    proc = subprocess.run(
        [sys.executable, str(ROOT / ".github" / "scripts" / "leak_gate.py"),
         "--json", "--require-git"],
        capture_output=True, text=True, cwd=str(ROOT), timeout=900)
    try:
        payload = json.loads(proc.stdout)
    except Exception:
        sweep.result("leak gate", False, "produced no JSON")
        sweep.finding("gate", "fatal", "leak_gate.py",
                      (proc.stdout + proc.stderr).strip()[:400])
        return
    for bucket in ("shape", "content", "denylist"):
        for hit in payload.get(bucket) or []:
            where = hit["file"] + (f":{hit['line']}" if "line" in hit else "")
            sweep.finding(bucket, "fatal", where,
                          f"{hit.get('rule') or hit.get('kind') or 'denylist'} "
                          f"{(hit.get('sample') or hit.get('term'))!r}")
    # DEFERRED IS SUMMARISED, NOT STREAMED. There are more than a hundred of
    # them and printing each one buries every other tier's output -- the same
    # failure that made whole-second durations unusable in the content tier.
    # Every one is still written to the JSONL; only the console is collapsed.
    deferred = payload.get("deferred") or []
    by_file = {}
    for hit in deferred:
        by_file.setdefault(hit["file"], []).append(hit)
    for rel, hits in sorted(by_file.items()):
        lines = sorted(h["line"] for h in hits)
        sweep.finding("deferred", "warn", f"{rel}:{lines[0]}-{lines[-1]}",
                      f"{len(hits)} figure(s) inside captured sample blocks. "
                      f"NO RULE CHECKS THESE -- the gate cannot tell the "
                      f"fixture from a real session", quiet_rows=hits)
    if not payload.get("denylist_ran"):
        sweep.notes.append("the denylist tier DID NOT RUN: no local denylist "
                           "on this machine, so no proper noun was checked "
                           "by anything")
    sweep.result("leak gate", proc.returncode == 0,
                 f"exit {proc.returncode}; {len(deferred)} deferred figure(s) "
                 f"NOT CHECKED by any rule")


def tier_corpus(sweep: Sweep) -> None:
    """Tier 5: exact comparison against what this machine has measured."""
    sweep.tier("tier 5  corpus -- does a shipped figure EQUAL a real one")
    state = ROOT / "state"
    broken = corpus.selftest(state)
    for line in broken:
        sweep.finding("corpus-selftest", "fatal", "oe/corpus.py", line)
    if broken:
        sweep.result("corpus tier", False, "the tier itself is broken")
        return

    exact, scaled, values = corpus.local_figures(state)
    tracked = package.git_tracked(ROOT) or []
    shipped = sorted(set(tracked))
    hard = soft = 0
    for rel in shipped:
        try:
            text = (ROOT / rel).read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        hits, advisory = corpus.scan(text, rel, exact, scaled)
        for hit in hits:
            hard += 1
            sweep.finding("corpus", "fatal", f"{hit.rel}:{hit.line}",
                          f"{hit.sample!r} is a value measured on this machine "
                          f"({hit.origin})")
        for hit in advisory:
            soft += 1
            if sweep.verbose:
                sweep.finding("corpus-scaled", "info", f"{hit.rel}:{hit.line}",
                              f"{hit.sample!r} == {hit.origin}")
    if soft and not sweep.verbose:
        sweep.notes.append(
            f"{soft} number(s) equal a local figure divided by a small "
            f"constant. Advisory: a quotient collides easily. Re-run with -v "
            f"to see them.")
    sweep.result("corpus tier", hard == 0,
                 f"{values:,} local values indexed; {hard} exact, {soft} scaled")


def _flags_exist(argv, env) -> list:
    """Flags in `argv` that this subcommand's parser does not define.

    THE SURFACE TIER MUST CHECK ITS OWN INVOCATIONS. Every earlier round of
    this work lost time to a check that was wrong rather than a tool that was
    broken -- an unquoted variable that never split into arguments, a scratch
    root that suppressed the migration under test, and, in this very tier's
    first draft, three flags that were simply invented. All three reported as
    `exit 2` and read exactly like a product failure. A wrong check is worse
    than a missing one, because it spends a round.
    """
    name = argv[0]
    proc = subprocess.run(
        [sys.executable, str(ROOT / "bin" / "oe"), name, "--help"],
        capture_output=True, text=True, cwd=str(ROOT), env=env, timeout=120)
    if proc.returncode != 0:
        return [f"`oe {name}` has no parser"]
    text = proc.stdout
    return [tok for tok in argv[1:]
            if tok.startswith("-") and tok not in text]


def tier_surface(sweep: Sweep, scratch: Path) -> None:
    """Tier 6: every command runs. --help-only ones are NAMED, not implied."""
    sweep.tier("tier 6  surface -- the commands actually run")
    env = dict(os.environ)
    env["OE_NO_COLOR"] = "1"
    ran = failed = 0
    for label, argv in READ_ONLY:
        argv = [tok.replace("{scratch}", str(scratch)) for tok in argv]
        bogus = _flags_exist(argv, env)
        if bogus:
            sweep.finding("harness", "fatal", f"sweep.py READ_ONLY[{label!r}]",
                          f"THIS CHECK IS WRONG, not the tool: "
                          f"{', '.join(bogus)} is not a flag of `oe {argv[0]}`")
            failed += 1
            continue
        proc = subprocess.run(
            [sys.executable, str(ROOT / "bin" / "oe"), *argv],
            capture_output=True, text=True, cwd=str(ROOT), env=env, timeout=600)
        ran += 1
        blob = proc.stdout + proc.stderr
        if "Traceback (most recent call last)" in blob:
            failed += 1
            tail = [ln for ln in blob.strip().splitlines() if ln.strip()][-1]
            sweep.finding("surface", "fatal", f"oe {label}", f"traceback: {tail}")
        elif proc.returncode not in (0, 1):
            failed += 1
            sweep.finding("surface", "fatal", f"oe {label}",
                          f"exit {proc.returncode}")
    covered = {argv[0] for _label, argv in READ_ONLY}
    listed = _subcommands()
    only_help = sorted(listed - covered)
    for name in only_help:
        proc = subprocess.run(
            [sys.executable, str(ROOT / "bin" / "oe"), name, "--help"],
            capture_output=True, text=True, cwd=str(ROOT), env=env, timeout=120)
        if proc.returncode != 0:
            sweep.finding("surface", "fatal", f"oe {name} --help",
                          f"exit {proc.returncode}")
            failed += 1
    if only_help:
        sweep.notes.append(
            f"{len(only_help)} command(s) were --help-checked only, because "
            f"running them writes: {', '.join(only_help)}. A parser that "
            f"imports is not a command that works.")
    sweep.result("surface", failed == 0,
                 f"{ran} run for real, {len(only_help)} --help only, "
                 f"{failed} failed")


def _subcommands():
    proc = subprocess.run(
        [sys.executable, str(ROOT / "bin" / "oe"), "--help"],
        capture_output=True, text=True, cwd=str(ROOT), timeout=120)
    for line in proc.stdout.splitlines():
        if line.strip().startswith("{") and line.strip().endswith("}"):
            return set(line.strip().strip("{}").split(","))
    return set()


def tier_drift(sweep: Sweep) -> None:
    """Tier 7: the bundle allowlist and git, cross-checked both ways."""
    sweep.tier("tier 7  drift -- allowlist against git")
    tracked = package.git_tracked(ROOT)
    if tracked is None:
        sweep.finding("drift", "fatal", ".", "not a git checkout of this tree")
        sweep.result("drift", False, "git could not answer")
        return
    staging = Path(tempfile.mkdtemp(prefix="oe-sweep-"))
    try:
        result = package.stage(ROOT, staging / package.BUNDLE_NAME)
        gaps = package.drift(ROOT, result.files)
    finally:
        shutil.rmtree(staging, ignore_errors=True)
    for rel in gaps.get("untracked_by_scan") or []:
        sweep.finding("drift", "warn", rel,
                      "git would publish it; the bundle allowlist never "
                      "scanned it")
    for rel in gaps.get("unseen_by_git") or []:
        sweep.finding("drift", "warn", rel,
                      "the bundle carries it; a clone would not")
    total = sum(len(v) for v in gaps.values())
    sweep.result("drift", total == 0,
                 f"{len(result.files)} in the bundle, {len(tracked)} in git, "
                 f"{total} disagreement(s)")


def tier_canary(sweep: Sweep) -> None:
    """Tier 0, run last because it is the slowest: can the gate be defeated?"""
    sweep.tier("tier 0  canary -- plant a leak and watch the gate")
    proc = subprocess.run(
        [sys.executable, str(ROOT / ".github" / "scripts" / "canary_leaks.py")],
        capture_output=True, text=True, cwd=str(ROOT), timeout=1800)
    blob = proc.stdout + proc.stderr
    for line in blob.splitlines():
        if line.strip().startswith("[FAIL]"):
            sweep.finding("canary", "fatal", "canary_leaks.py",
                          line.strip()[6:].strip())
    tail = [ln for ln in blob.strip().splitlines() if ln.strip()]
    sweep.result("canary", proc.returncode == 0,
                 tail[-1][:120] if tail else f"exit {proc.returncode}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--quick", action="store_true",
                        help="skip the surface and canary tiers")
    parser.add_argument("--since", action="store_true",
                        help="report only findings this run ADDED against the "
                             "recorded baseline, and say what it dropped")
    parser.add_argument("--save", action="store_true",
                        help="record this run as the new baseline")
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--out", default=str(ROOT / "state" / "sweep" /
                                             "findings.jsonl"))
    args = parser.parse_args()

    started = time.time()
    sweep = Sweep(Path(args.out), args.verbose)
    sweep.say(f"sweep: {ROOT}")
    try:
        tier_gate(sweep)
        tier_corpus(sweep)
        tier_drift(sweep)
        if not args.quick:
            scratch = Path(tempfile.mkdtemp(prefix="oe-surface-"))
            try:
                tier_surface(sweep, scratch)
            finally:
                shutil.rmtree(scratch, ignore_errors=True)
            tier_canary(sweep)
    finally:
        sweep.close()

    sweep.tier("blind spots -- what NO tier above looked for")
    for line in BLIND_SPOTS:
        sweep.say(f"  - {line}")
    for line in sweep.notes:
        sweep.say(f"  - {line}")

    fatal = sweep.fatal
    warn = [f for f in sweep.findings if f["severity"] == "warn"]

    if args.since and BASELINE.exists():
        old = json.loads(BASELINE.read_text())
        seen = {(f["tier"], f["where"], f["what"]) for f in old["findings"]}
        now = {(f["tier"], f["where"], f["what"]) for f in sweep.findings}
        sweep.tier("delta against the recorded baseline")
        added = sorted(now - seen)
        gone = sorted(seen - now)
        sweep.say(f"  added {len(added)}, resolved {len(gone)}")
        for tier, where, what in added:
            sweep.say(f"  NEW  {tier}  {where}  {what}")

    record = {
        "elapsed": round(time.time() - started, 1),
        "findings": sweep.findings,
        "tiers": sweep.tiers,
        "notes": sweep.notes,
        "blind_spots": list(BLIND_SPOTS),
        "fatal": len(fatal),
        "warn": len(warn),
    }
    if args.save:
        BASELINE.parent.mkdir(parents=True, exist_ok=True)
        BASELINE.write_text(json.dumps(record, indent=2, sort_keys=True))
        sweep.say(f"\nbaseline recorded: {BASELINE.name}")

    sweep.tier("result")
    for name, info in sweep.tiers.items():
        sweep.say(f"  {'PASS' if info['ok'] else 'FAIL'}  {name}")
    sweep.say(f"\n  {len(fatal)} fatal, {len(warn)} warn, "
              f"{len(BLIND_SPOTS) + len(sweep.notes)} thing(s) NOT checked "
              f"by anything -- in {record['elapsed']}s")
    if args.json:
        print(json.dumps(record, indent=2, sort_keys=True))
    return 1 if fatal else 0


if __name__ == "__main__":
    raise SystemExit(main())
