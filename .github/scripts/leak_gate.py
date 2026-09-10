#!/usr/bin/env python3
"""CI leak gate: the machine-independent tiers of `oe package`, plus hygiene.

Three checks, in this order:

  1. HYGIENE -- nothing forbidden is tracked. .gitignore is an allowlist, but
     it does nothing about a file that is already tracked, so the tracked list
     is asserted directly against a small denylist (state/, reports/, config
     .json, backups, temp files, logs, bundles, __pycache__).

  2. SHAPE -- no PII-SHAPED string in anything that would be published. The
     scanned set is the union of what `oe package`'s allowlist admits and what
     git actually tracks, which is the same union oe/package.py scans, and for
     the same reason: the allowlist and the checkout are two different answers
     to "what ships", and a leak hides in the gap between them.

  3. CONTENT -- no FIGURE that was measured on the author's corpus or machine.
     This tier exists because tiers 1 and 2 were both blind to it: an ordinary
     number carries no shape at all, and a planted canary carrying a dollar
     amount, a corpus byte total, an employer name and a private filename
     passed this gate green with the archive written. What it looks for is
     defined in oe/package.py under "tier 3: CONTENT"; the reviewed exemptions
     are CONTENT_ALLOW beside it.

  4. DENYLIST -- words a human decided must never ship: an employer, a client,
     a private repository, a source-file basename. These have no shape, so no
     rule can find them; only a list can, and the list is the thing that must
     not ship. It is therefore read from OUTSIDE the tree ($OE_LEAK_DENYLIST,
     else ~/.config/overwatch-enforcer/leak-denylist.txt) and does not exist on
     a runner. WHEN IT IS ABSENT THIS TIER DOES NOT RUN, and the gate prints
     that fact instead of letting a green result imply it did.

Deliberately NOT `oe package` itself. That command has a fourth tier -- the
IDENTITY tier -- which matches the real email, username, hostname and account
ids of the machine running it. On a hosted runner that machine is an ephemeral
VM whose identity this repository cannot possibly contain, so the check has no
authority there. It is also actively wrong: a runner's $USER is `runner`, a
word that appears in oe/redact.py's own generic-username list and in the
README, so tier 1 would report fatal leaks on every single build. Tier 1
belongs on a maintainer's machine, where `oe package` still enforces it before
a bundle is built -- see CONTRIBUTING.md.

Tiers 2 and 3 are machine-independent: a regex sweep for shapes and for
figures, minus two reviewed tables in oe/package.py. They mean exactly the same
thing on a runner as they do at home, which is why CI can honestly enforce
them.

=== WHAT THIS GATE CAN AND CANNOT SEE ===

A green result here is evidence about a list of specific rules, and nothing
more. Read as proof of anything wider, it becomes the reason a class survives
a sweep that reported clean.

MECHANICAL -- the gate finds these, and a regression is caught by the
self-tests that run on every invocation plus .github/scripts/canary_leaks.py:

  * a forbidden path in the tracked list (state/, reports/, backups, logs, ...)
  * a home path, an email, a uuid, a branch name, an issue key
  * a currency amount with a symbol, above zero, that is not a per-Mtok price
  * an amount-shaped number with NO symbol sitting on a line with a money word
  * a byte/token/request/session/file/line/call/millisecond absolute, written
    either with its unit welded on or as a four-figure number beside a corpus
    noun
  * a line whose phrasing MARKS a figure as observed -- "measured", "on this
    machine", "on the real", "this corpus", "in practice here"
  * a percentage within two lines of a numeric rate, where the two multiply
    back into an amount

NOT MECHANICAL -- a human must read for these before the first push. Nothing
in this file looks for any of them:

  * an employer, product, client, repository or person's NAME, and a private
    source-file BASENAME, UNLESS this machine has a local denylist naming
    them. A name is only a word and `rows.ts` is indistinguishable from an
    invented example, so tier 4 is a list, not a rule -- and there is no list
    in CI. On a runner, proper nouns are a human read, exactly as
    CONTRIBUTING.md says.
  * whether a figure inside a fenced sample-output block in docs/ came from an
    invented fixture or from a real session. The content tier cannot tell a
    capture of the documentation fixture from a capture of the author's own
    report. Those hits are COUNTED and PRINTED below as "deferred", never
    silently dropped and never fatal -- read them.
  * a duration in whole seconds, hours or minutes. `s`, `h` and `min` are not
    units in the content tier: in this tree they are overwhelmingly timeouts,
    poll intervals and CSS animation lengths, and including them buried the
    real hits under a hundred false ones.
  * a small integer with a unit -- "bytes / 4 tokens" -- which is below the
    content tier's floor and therefore invisible even when it was measured.
  * a figure written in words, or split across two lines. Every rule here is
    line-local.
  * a wrong entry in PLACEHOLDERS or CONTENT_ALLOW. An exemption is a
    permanent hole in the gate that only review closes, which is why each one
    carries a reason.
  * anything in a file that BOTH the allowlist and git miss. drift() compares
    the two lists against each other; a file in neither is invisible to both.

Run it anywhere:  python3 .github/scripts/leak_gate.py
In CI:            python3 .github/scripts/leak_gate.py --require-git
Try to defeat it: python3 .github/scripts/canary_leaks.py
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import sys
import tempfile

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from oe import package, redact  # noqa: E402


#: (pattern, why it must never be tracked). Matched against repo-relative
#: POSIX paths as git prints them.
FORBIDDEN = (
    (re.compile(r"(^|/)state/"),
     "runtime state: the account map, the session map, the cost cache"),
    (re.compile(r"(^|/)reports/"),
     "generated reports; they are per-machine and can carry session titles"),
    (re.compile(r"^config\.json$"),
     "machine-local config; it is rewritten at runtime, use config.example.json"),
    (re.compile(r"(^|/)__pycache__/"), "byte-compiled Python"),
    (re.compile(r"\.py[co]$"), "byte-compiled Python"),
    (re.compile(r"\.bak(-[0-9]+)?$"), "backup left beside a file the tool rewrote"),
    (re.compile(r"\.tmp$"), "half-written file from an interrupted atomic write"),
    (re.compile(r"\.orig$|\.rej$"), "merge leftovers"),
    (re.compile(r"\.log$"), "logs name sessions and absolute paths"),
    (re.compile(r"\.tar\.gz(\.part)?$"), "a bundle built by `oe package`"),
    (re.compile(r"(^|/)\.DS_Store$"), "macOS directory metadata"),
    (re.compile(r"^\.claude/"), "this checkout's own editor settings"),
)

#: Paths that must pass, and paths that must fail. Run on every invocation so
#: a broken predicate cannot pass silently -- a gate nobody checks is worse
#: than no gate, because it implies a safety it is not providing.
_MUST_PASS = (
    ".gitignore", ".gitattributes", "LICENSE", "README.md", "CONTRIBUTING.md",
    "SECURITY.md", "install.py", "extract_pricing.py", "config.example.json",
    "oe/package.py", "oe/pricing.py", "hooks/session_start.py", "bin/oe",
    "bin/oe-watch", ".github/workflows/ci.yml", ".github/scripts/leak_gate.py",
)
_MUST_FAIL = (
    "state/session-map.json", "state/accounts.json", "reports/index.html",
    "oe/__pycache__/paths.pyc", "oe/pricing.pyo", "oe/pricing.py.bak",
    "oe/pricing.py.tmp", "config.json", "overwatch-enforcer.tar.gz",
    "state/watcher-abc.log", "install.py.bak-1", ".DS_Store",
    ".claude/settings.local.json", "settings.json.orig",
)

#: Content-tier probes, run on every invocation for the same reason as the
#: path predicate above. Each probe is scanned as if it were the whole of a
#: shipped Python file, so the comment marker matters.
#:
#: THE FIGURES ARE NOT WRITTEN INTO THE TEMPLATES. A probe that spelled an
#: amount out in a comment would BE a figure in a shipped file, and this gate
#: correctly flags any draft that does that. The numbers live as
#: NUMBER tokens in the tuple below, which the content tier does not scan --
#: it reads comments, docstrings and string literals -- and the sentence is
#: assembled at runtime. They are all invented: repeated digits and round
#: values that no measurement would ever land on.
#:
#: MUST FAIL -- one line each, the shapes the class actually takes here.
_CONTENT_MUST_FAIL = (
    ("money with a symbol",
     "# the whole run cost ${:,.2f} before lunch", (412.90,)),
    ("money with no symbol",
     "# total spend for the week was {:,.2f} across both", (512.40,)),
    ("a corpus byte total",
     "# read every transcript: {:,} files, {:,} MB in one pass", (777, 888)),
    ("a token count",
     "# the window carried {:,} tokens before the compact", (11111111,)),
    ("a request count",
     "# {:,} requests went through the main loop", (22222,)),
    ("a session count",
     "# averaged over the {} sessions this was built against", (33,)),
    ("a file size",
     "# this module is {:,} lines and nothing imports it lazily", (4444,)),
    ("a timing",
     "# the cold guard call measured {} ms on this machine", (55.5,)),
    ("observation phrasing",
     "# measured on this machine at {} carriers a window", (666,)),
    ("a percentage beside a rate",
     "# {}% of it was repeat, at ${}/1k that is real money", (77.7, 0.999)),
)
#: MUST PASS -- benign strings a high-recall rule would love to eat.
_CONTENT_MUST_PASS = (
    ("Anthropic list prices", "# Opus is $15.00 / Mtok in and $75.00 per Mtok out"),
    ("a version number", "# requires SQLite 3.43.0 or newer; this build has 3.46.1"),
    ("HTTP status codes", "# retry on 429 and 503, give up on 404"),
    ("a units-conversion table", "# 1 KB is 1024 bytes; 1 MB is 1024 KB"),
    ("a SQL limit", 'CUTOFF = "SELECT rowid FROM docs LIMIT 5000"'),
    ("an ANSI colour code", 'ALT_SCREEN = "\\x1b[?1049h" + "\\x1b[38;5;244m"'),
    ("a regex character class", 'KEY = re.compile(r"[A-Z]{1,9}-[0-9]{1,6}")'),
    ("a timeout in seconds", "# settings.json gives this hook 180s; stop first"),
    ("a poll interval", "# a 5 s poll is affordable for hours"),
    ("a ratio with no absolute", "# a measured 40.4% false-block rate, so it went"),
    ("a divisor", "# context cost is bytes / 4 tokens, written to cache once"),
)


def forbidden_reason(rel: str):
    """Why this path must never be tracked, or None if it is fine."""
    for pattern, reason in FORBIDDEN:
        if pattern.search(rel):
            return reason
    return None


def _content_fatal(source: str):
    """The content-tier hits a one-line Python source would produce."""
    fatal, _allowed, _deferred = package.content_leaks(source + "\n", "probe.py")
    return fatal


def selftest() -> int:
    bad = []
    for rel in _MUST_PASS:
        reason = forbidden_reason(rel)
        if reason:
            bad.append(f"false positive: {rel} rejected as {reason!r}")
    for rel in _MUST_FAIL:
        if forbidden_reason(rel) is None:
            bad.append(f"false negative: {rel} was allowed")
    for label, template, values in _CONTENT_MUST_FAIL:
        source = template.format(*values)
        if not _content_fatal(source):
            bad.append(f"content tier is blind to {label}: {source!r}")
    for label, source in _CONTENT_MUST_PASS:
        hits = _content_fatal(source)
        if hits:
            bad.append(f"content tier eats {label}: "
                       f"{[h.describe() for h in hits]}")
    if bad:
        print("a gate predicate is broken:")
        for line in bad:
            print(f"  {line}")
        return 1
    print(f"predicate self-test: {len(_MUST_PASS)} paths allowed, "
          f"{len(_MUST_FAIL)} rejected; content tier caught "
          f"{len(_CONTENT_MUST_FAIL)}/{len(_CONTENT_MUST_FAIL)} planted figures "
          f"and passed {len(_CONTENT_MUST_PASS)}/{len(_CONTENT_MUST_PASS)} "
          f"benign ones")
    return 0


def hygiene(tracked) -> int:
    hits = [(rel, forbidden_reason(rel)) for rel in tracked]
    hits = [(rel, why) for rel, why in hits if why]
    if hits:
        print(f"\n{len(hits)} FILE(S) MUST NOT BE TRACKED:")
        for rel, why in hits:
            print(f"  {rel}  -- {why}")
        print("\n.gitignore does not untrack a file that is already tracked.")
        print("Use `git rm --cached <path>` and commit that.")
        return 1
    print(f"tracked file list is clean ({len(tracked)} files)")
    return 0


def scan_published(tracked, quiet: bool = False):
    """Run tiers 2, 3 and 4 over the allowlist unioned with what git tracks.

    Returns a dict: shape, content, denylist, allowed, deferred, denylist_source.
    """
    staging = Path(tempfile.mkdtemp(prefix="oe-leak-gate-"))
    shape_leaks = []
    content = []
    deferred = []
    denied_hits = []
    allowed = {}
    denied, denylist_source = package.local_denylist()
    try:
        result = package.stage(ROOT, staging / package.BUNDLE_NAME)
        shipped = set(result.files)
        extra = sorted(set(tracked) - shipped)
        if not quiet:
            print(f"allowlist admits {len(shipped)} files; "
                  f"git adds {len(extra)} more")
            for name in result.skipped:
                print(f"  not shipped: {name}")
            # Informational, not fatal. A file can legitimately be in the clone
            # and not in the bundle -- .gitattributes and these CI scripts are
            # exactly that, and .gitattributes marks .github/ export-ignore to
            # say so. What matters is that it is SCANNED, which the union does.
            for rel in extra:
                print(f"  tracked, outside the bundle allowlist, "
                      f"scanned anyway: {rel}")

        for rel in sorted(shipped) + extra:
            # Allowlisted files are read from the staging copy, where
            # config.json has already been rewritten to the code defaults.
            # Everything else is read from the checkout.
            path = (staging / package.BUNDLE_NAME / rel) if rel in shipped \
                else (ROOT / rel)
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except Exception as exc:
                if not quiet:
                    print(f"  unreadable, not scanned: {rel} "
                          f"({type(exc).__name__})")
                continue

            for finding in redact.audit(text, where=rel):
                if finding.severity != "block":
                    continue
                if finding.kind in ("identity", "user"):
                    continue  # tier 1; see the module docstring
                reason = package.placeholder_reason(
                    finding.kind, finding.sample, text, finding.offset)
                if reason:
                    allowed[reason] = allowed.get(reason, 0) + 1
                    continue
                shape_leaks.append(
                    (rel, finding.kind, finding.offset, finding.sample))

            fatal, content_ok, put_off = package.content_leaks(text, rel)
            for hit in fatal:
                content.append((rel, hit.line, hit.rule, hit.sample))
            for reason, count in content_ok.items():
                allowed[reason] = allowed.get(reason, 0) + count
            for hit in put_off:
                deferred.append((rel, hit.line, hit.rule, hit.sample))

            for term, at in package.denylist_hits(text, denied):
                denied_hits.append((rel, at, term))
    finally:
        shutil.rmtree(staging, ignore_errors=True)
    return {
        "shape": shape_leaks,
        "content": content,
        "denylist": denied_hits,
        "allowed": allowed,
        "deferred": deferred,
        "denylist_source": denylist_source,
        "denylist_terms": len(denied),
    }


def shapes(tracked, as_json: bool = False) -> int:
    found = scan_published(tracked, quiet=as_json)
    shape_leaks = found["shape"]
    content = found["content"]
    deferred = found["deferred"]
    allowed = found["allowed"]

    if as_json:
        print(json.dumps({
            "ok": not (shape_leaks or content or found["denylist"]),
            "shape": [{"file": r, "kind": k, "offset": o, "sample": s}
                      for r, k, o, s in shape_leaks],
            "content": [{"file": r, "line": n, "rule": u, "sample": s}
                        for r, n, u, s in content],
            "denylist": [{"file": r, "offset": o, "term": t}
                         for r, o, t in found["denylist"]],
            "deferred": [{"file": r, "line": n, "rule": u, "sample": s}
                         for r, n, u, s in deferred],
            "allowed": allowed,
            "denylist_ran": bool(found["denylist_source"]),
            "denylist_terms": found["denylist_terms"],
        }, indent=2, sort_keys=True))
        return 0 if not (shape_leaks or content or found["denylist"]) else 1

    for reason, count in sorted(allowed.items()):
        print(f"  allowed x{count}: {reason}")

    if deferred:
        print(f"\n{len(deferred)} figure(s) inside captured sample-output "
              f"blocks in docs/. NOT CHECKED -- this gate cannot tell a capture")
        print("of the documentation fixture from a capture of a real session.")
        print("A human confirms the fixture is invented; the gate cannot:")
        by_file = {}
        for rel, line, rule, sample in deferred:
            by_file.setdefault(rel, []).append(line)
        for rel, at in sorted(by_file.items()):
            span = f"{min(at)}-{max(at)}" if len(at) > 1 else str(at[0])
            print(f"  {rel}  x{len(at)}  (lines {span})")

    rc = 0
    if shape_leaks:
        print(f"\n{len(shape_leaks)} PII-SHAPED STRING(S) IN PUBLISHED FILES:")
        for rel, kind, offset, sample in shape_leaks:
            print(f"  {rel}  {kind}@{offset}  {sample!r}")
        print("\nEither remove the string, or add it to PLACEHOLDERS in")
        print("oe/package.py with a one-line reason. That table is reviewed:")
        print("an entry earns its place by being a value that cannot identify")
        print("anybody -- an invented path, a regex class, an encoding name.")
        rc = 1
    else:
        print("shape tier clean")

    if found["denylist_source"]:
        print(f"denylist tier ran: {found['denylist_terms']} local term(s)")
    else:
        # ~-relative on purpose: this line goes into CI logs, and the absolute
        # form of the default path spells out a username.
        where = package.denylist_path()
        try:
            where = "~/" + str(Path(where).relative_to(Path.home()))
        except Exception:
            where = "the default location"
        print("denylist tier DID NOT RUN: no local denylist "
              f"(${package.DENYLIST_ENV}, else {where}). Employer, client, "
              "repository and private-basename checks are a HUMAN READ on "
              "this run.")
    if found["denylist"]:
        print(f"\n{len(found['denylist'])} DENYLISTED TERM(S) IN PUBLISHED FILES:")
        for rel, at, term in found["denylist"]:
            print(f"  {rel}  denylist@{at}  {term!r}")
        print("\nA human put this word on the local denylist. Remove it from")
        print("the tree; it is not something an exemption can make safe.")
        rc = 1

    if content:
        print(f"\n{len(content)} MEASURED FIGURE(S) IN PUBLISHED FILES:")
        for rel, line, rule, sample in content:
            print(f"  {rel}:{line}  {rule}  {sample!r}")
        print("\nA figure measured on the author's corpus or machine does not")
        print("ship. Replace it with an order of magnitude, a ratio, or an")
        print("invented round number -- do NOT scale a real one, a real figure")
        print("over a constant is still a real figure. If the number genuinely")
        print("cannot identify anything, add it to CONTENT_ALLOW in")
        print("oe/package.py with a one-line reason.")
        rc = 1
    else:
        print("content tier clean")
    return rc


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--require-git", action="store_true",
        help="fail if this is not a git checkout OF THIS TREE, instead of "
             "scanning only the allowlist (CI passes this so the gate can "
             "never pass vacuously)")
    parser.add_argument(
        "--json", action="store_true",
        help="print the finding set as JSON instead of prose. Same exit code. "
             "This is what .github/scripts/canary_leaks.py reads, so a canary "
             "asserts on the gate's real answer rather than on a regex over "
             "its prose.")
    args = parser.parse_args()

    # The self-test runs on EVERY invocation, --json included. A machine
    # reading the JSON must not be the one path that skips the check that the
    # predicates still work; it just gets the summary on stderr so the JSON on
    # stdout stays parseable.
    stdout, sys.stdout = sys.stdout, (sys.stderr if args.json else sys.stdout)
    try:
        rc = selftest()
    finally:
        sys.stdout = stdout
    if rc:
        return rc

    tracked = package.git_tracked(ROOT)
    if tracked is None:
        if args.require_git:
            print("\nnot a git checkout of this tree, or git is unavailable.")
            print("git_tracked() also returns None when the git root is NOT")
            print("the install root -- a checkout sitting inside somebody")
            print("else's repository -- because git would then answer for that")
            print("repository. Either way the tracked-file check cannot run and")
            print("this gate refuses to report success.")
            return 1
        if not args.json:
            print("not a git checkout of this tree; scanning the allowlist only "
                  "(pass --require-git to make this fatal)")
        tracked = []
    elif not tracked:
        # A real checkout of this repository tracks dozens of files. Zero means
        # the answer came from somewhere that is not this tree, and every
        # git-derived check below would then assert nothing at all.
        print("\ngit reported ZERO files for this tree. A checkout of this")
        print("repository can never legitimately track nothing, so the")
        print("tracked-file check and the allowlist-vs-git cross-check would")
        print("both pass by asserting nothing. Refusing to report success.")
        return 1
    elif not args.json:
        rc = hygiene(tracked)
        if rc:
            return rc

    return shapes(tracked, as_json=args.json)


if __name__ == "__main__":
    raise SystemExit(main())
