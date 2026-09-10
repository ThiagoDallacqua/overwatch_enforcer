"""Build the shareable bundle -- `oe package`.

Packaging is an ALLOWLIST, exactly like the reports. A denylist ships whatever
nobody thought to exclude, and the thing nobody thinks to exclude here is
`state/`, which reaches tens of megabytes holding the account map (a real
email), the session map that undoes every pseudonym in every report, a cost
cache full of absolute paths and session titles, and a context database built
from whatever source tree this machine works in. Forgetting it once hands a
colleague the key to all of it.

So nothing travels unless a rule below names it, and the staged copy is then
re-scanned with the same auditor the reports use. Three tiers of finding:

  identity  -- the real values of THIS machine (email, username, hostname,
               account and machine uuids), matched as literal needles. Always
               fatal, no override. A bundle that carries one is not shareable
               under any argument.
  shape     -- something merely SHAPED like personal data: `/home/x` in a
               docstring, `feature/x` in a comment, `a@b.co` in a self-test.
               Fatal too, unless the exact string is in PLACEHOLDERS below,
               which is a reviewed list with a reason per entry.
  content   -- a number that is TRUE about this machine: an amount, a corpus
               byte or token or request total, a file size, a timing. Nothing
               about its SHAPE says "private", only its provenance, so this
               tier reads the words around it. Fatal, unless the exact sample
               is in CONTENT_ALLOW, reviewed the same way.

That split is what lets the check stay strict without going off constantly:
adding the packager's own home path to a docstring fails the build, while
placeholders the code needs pass, because someone reviewed them once.
"""

from __future__ import annotations

import ast
import hashlib
import json
import os
import re
import shutil
import tarfile
import tempfile

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from . import paths
from . import redact as redact_mod
from .version import VERSION

#: The directory every member of the tarball hangs off, and the directory
#: `tar xzf` leaves behind. STABLE ACROSS RELEASES on purpose: the documented
#: second line of an offline install is `python3 overwatch-enforcer/install.py`
#: and it should not need rewriting for every version. The version travels in
#: the archive's FILE name instead -- see archive_name() -- which is what a
#: downloads folder holding three of these needs to tell them apart.
BUNDLE_NAME = "overwatch-enforcer"


def archive_name(version: Optional[str] = None) -> str:
    """The default filename for a bundle built from this tree.

    Both callers -- `oe package` and the release workflow -- ask the code for
    this rather than formatting it themselves, so there is exactly one
    definition of what a release asset is called and no format string to keep
    in sync with a shell script.
    """
    return f"{BUNDLE_NAME}-{version or VERSION}.tar.gz"

# --- what ships -------------------------------------------------------------

#: Files at the top of the install root. Anything not named here stays home.
ROOT_FILES: Tuple[str, ...] = (
    "README.md",
    "install.py",
    "extract_pricing.py",
    # config.json is DELIBERATELY ABSENT. It is the one machine-local file in
    # the tree, and shipping a rewritten copy of it meant a bundle and a clone
    # installed differently -- the clone has no config.json and install.py
    # seeds one from the example, which is a fully supported state. Shipping it
    # bought nothing and kept a sanitisation path on the risk surface for a
    # file that did not need to be there. sanitised_config() still runs, to
    # REPORT which machine-local keys exist and are not leaving.
    ".gitignore",       # documents the state/ rule for anyone who re-packages
    # The single source of truth for the version. install.py, oe/version.py and
    # the release workflow all read it, so a bundle or clone without it is a
    # tool that cannot say what it is.
    "VERSION",
    "LICENSE",
    "CONTRIBUTING.md",
    "SECURITY.md",
    ".gitattributes",
    # The pristine config install.py seeds config.json from. A bundle without
    # it ships a tool whose installer cannot do that step.
    "config.example.json",
)

#: Directory -> the file extensions that may leave it. `None` means "an
#: extensionless executable", which is how bin/oe, bin/oe-watch and bin/oe-repair
#: are named. .gitignore names those three one by one, so the two lists agree.
#: A backup can never sneak through: `bin/oe.bak-N` has a dot, and
#: `oe/ledger.py.bak-N` has suffix `.bak-N`, so neither matches its rule.
TREES: Dict[str, Optional[frozenset]] = {
    "oe": frozenset({".py"}),
    "hooks": frozenset({".py"}),
    "bin": None,
    # CI definitions. They are published with everything else, so they get
    # scanned with everything else -- a workflow file is as capable of carrying
    # a real path or an org name as any docstring.
    ".github": frozenset({".yml", ".yaml", ".md", ".py"}),
    # The README is sharded into docs/ so the landing page stays readable.
    # They are published, so they are scanned like everything else.
    "docs": frozenset({".md"}),
}

#: Config keys whose value is about this machine and never about the tool.
#: Everything ships as the code default; these are called out by name so the
#: packager can report what it dropped rather than silently flattening it.
MACHINE_KEYS: Tuple[str, ...] = ("reports_root", "accounts")

# --- shape findings that are known-good -------------------------------------

#: (kind, exact sample) -> why it is not a leak. Reviewed by hand. An entry
#: earns its place by being a value that cannot identify anybody: a made-up
#: path, a regex character class, an encoding name, a unit.
PLACEHOLDERS: Dict[Tuple[str, str], str] = {
    ("home", "/home/x"):        "docs/doctest placeholder path",
    ("home", "/home/u"):        "docs/doctest placeholder path",
    ("home", "/home/someone"):  "docs placeholder path",
    ("home", "/Users/x"):       "docs placeholder path (macOS spelling)",
    ("branch", "feature/x"):    "redaction self-test probe in bin/oe",
    ("branch", "feature/abc-913-..."): "comment illustrating the branch pattern",
    ("email", "a@b.co"):        "redaction self-test probe in bin/oe",
    ("uuid", "11111111-2222-3333-4444-555555555555"):
                                "redaction self-test probe in bin/oe",
    ("ticket", "ABC-1"):        "redaction self-test probe in bin/oe",
    ("ticket", "ABC-913"):      "neutral example key in redact.py's docstring",
    ("ticket", "abc-913"):      "neutral example key, lowercase branch spelling",
    ("ticket", "z0-9"):         "regex character class",
    ("ticket", "Z0-9"):         "regex character class",
    ("ticket", "ISO-8601"):     "date standard",
    ("ticket", "UTC-4"):        "timezone offset",
    ("ticket", "GMT-14"):       "timezone offset",
    ("ticket", "latin-1"):      "text encoding",
    ("ticket", "utf-8"):        "text encoding",
    ("ticket", "bak-1"):        "backup-suffix example",
    ("ticket", "bak-2"):        "backup-suffix example, the second rotation",
    ("ticket", "aes-256"):      "cipher name in a redaction example",
    ("ticket", "AES-256"):      "cipher name in a redaction example",
    ("ticket", "gpt-5"):        "a rival vendor's model id, named in the comment "
                                "that explains why the model-prefix rule is narrow",
    ("home", "/home/ana"):      "invented three-letter-username example in the "
                                "docs' username-boundary rule",
    ("home", "/home/maxwell"):  "invented long-username example in the comment "
                                "on redact.py's username-boundary rule",
    ("uuid", "3f5c1a90-2d44-4b71-9c0e-7a1b6d820e11"):
                                "the documentation fixture's invented session id, "
                                "used by every captured payload block in docs/",
    ("ticket", "secondary-2"):  "account-label example",
    ("ticket", "top-20"):       "a count, not a key",
    ("ticket", "then-6"):       "prose fragment ('... and then-6 ...')",
    ("ticket", "lo-1"):         "line-range arithmetic in a comment",
}


#: A release asset is named `overwatch-enforcer-1.0.0.tar.gz`, and the tool's
#: own name glued to a major version is the generic issue-key shape, so every
#: release note that spells the asset name out would break the build. Exempted
#: by RULE, not by an entry that would need rewriting for every version.
_OWN_ASSET_RE = re.compile(
    re.escape(BUNDLE_NAME) + r"-\d+\.\d+\.\d+", re.I)


def placeholder_reason(kind: str, sample: str, text: Optional[str] = None,
                       offset: Optional[int] = None) -> Optional[str]:
    """Why this shape-hit is allowed, or None if it is not.

    `text`/`offset` are optional context. They are what lets a rule ask WHERE
    the match sits rather than only what it says, which is the difference
    between exempting one hardcoded version string and exempting the tool's own
    release filename for every version it will ever have.
    """
    reason = PLACEHOLDERS.get((kind, sample))
    if reason:
        return reason
    # Model ids ('claude-opus-5') match the ticket shape and are emitted on
    # purpose; redact already classifies them, so mirror that rather than
    # restate the catalog here.
    if kind == "ticket" and sample.lower() in redact_mod._safe_ticket_shapes():
        return "model id / known-safe token"
    if kind == "ticket" and text is not None and offset is not None:
        for match in _OWN_ASSET_RE.finditer(text):
            if match.start() <= offset < match.end():
                return "this tool's own release-asset filename"
    return None


#: The single place a real name is not a leak. A licence is only enforceable if
#: it names the copyright holder, and the holder here is the repo owner, whose
#: name is already the public GitHub account. The exception is deliberately
#: narrow -- one file, one line prefix -- because "trust this whole file" is how
#: a gate stops being a gate: anything at all could then hide in LICENSE.
IDENTITY_EXEMPT_LINES: Dict[str, Tuple[str, ...]] = {
    "LICENSE": ("copyright",),
}


#: A forge URL carries the owner's account name in its path, and that name is
#: public by construction -- it is how anyone reaches the repository at all.
#: Matched as a PATTERN rather than a hardcoded account, so this stays true for
#: whoever forks the tool next; hardcoding one name would make the gate a
#: statement about one person instead of a rule.
_FORGE_URL_RE = re.compile(
    r"\b(?:https?://|git@)?(?:www\.)?"
    r"(?:github\.com|gitlab\.com|codeberg\.org|bitbucket\.org)"
    r"[/:][\w.-]+/[\w.-]+", re.I)


def _inside_forge_url(text: str, offset: int) -> bool:
    """True when `offset` falls inside a repository URL.

    Bounded to the line holding the offset so a URL cannot vouch for something
    three paragraphs away.
    """
    start = text.rfind("\n", 0, offset) + 1
    end = text.find("\n", offset)
    end = end if end >= 0 else len(text)
    for match in _FORGE_URL_RE.finditer(text[start:end]):
        if match.start() <= offset - start < match.end():
            return True
    return False


def identity_exempt(rel: str, text: str, offset: int) -> bool:
    """True when this identity hit sits somewhere allowed to carry it."""
    if _inside_forge_url(text, offset):
        return True
    prefixes = IDENTITY_EXEMPT_LINES.get(rel)
    if not prefixes:
        return False
    start = text.rfind("\n", 0, offset) + 1
    end = text.find("\n", offset)
    line = text[start: end if end >= 0 else len(text)].strip().lower()
    return line.startswith(prefixes)


# --- tier 3: CONTENT -- figures that were measured, not invented -------------
#
# Tiers 1 and 2 ask "does this string LOOK like somebody's data". Neither can
# see a figure that is not shaped like an identifier at all -- an ordinary
# number that simply happens to be TRUE about the machine the file was written
# on:
#
#     a dollar amount, with or without the sign (a bare two-decimal number in
#     a comment reads as ordinary prose); a corpus byte total; a token, request
#     or session count; a file size; a timing; a percentage sitting beside a
#     rate, so that the two multiply back into an amount.
#
# Individually each looks like documentation. Together they reconstruct how
# much was spent, on what, and how big a private corpus is -- and the pieces
# MOVE between files under editing, so deleting today's instances does not stop
# tomorrow's. Only a rule does that.
#
# What is NOT in the class, and must never trip this tier:
#   - Anthropic's published per-Mtok list prices. They are public.
#   - A ratio, a multiplier, or a percentage carrying a finding on its own,
#     with no absolute next to it.
#   - Anything computed at RUNTIME from the running user's own data. This tier
#     reads source text, so a f-string that will print a number at runtime is
#     only interesting for the LITERALS written into it.
#
# Recall is deliberately favoured over precision: a rule that reports a benign
# number costs one reviewed allowlist entry, while a rule that misses a real
# one costs a release. CONTENT_ALLOW below is that allowlist, and it carries a
# reason per entry exactly like PLACEHOLDERS.

#: Number, with optional thousands separators. Used everywhere below so that
#: `1,309` and `1309` are one concept.
_N = r"(?:\d{1,3}(?:,\d{3})+(?:\.\d+)?|\d+(?:\.\d+)?)"

#: A standalone number. The lookbehind refuses a digit glued to a word, a
#: dotted version component, a `#rrggbb` colour and a `-` inside an id; the
#: lookahead refuses the head of `3.46.1` and of `1,309,000`.
_NUM_RE = re.compile(r"(?<![\w.,$#])(?<!-)" + _N + r"(?![\w.]|,\d)")

#: A currency amount. `$`, `€` or `£`, an optional space, then the number.
_CURRENCY_RE = re.compile(r"(?<![\w])([$€£])\s?(" + _N + r")([kKmM])?(?![\w.])")

#: A number with a unit welded to it -- a size, a count or a duration written
#: as digits then a unit, with or without a space and with or without a
#: magnitude prefix.
#: `s`, `h` and `min` are deliberately ABSENT -- see the reach note in
#: leak_gate.py. Whole-second durations in this tree are overwhelmingly
#: timeouts, poll intervals and CSS animation lengths, none of which say
#: anything about anybody's corpus, and including them buried the real hits.
_UNIT_RE = re.compile(
    r"(?<![\w.,$#])(?<!-)(" + _N + r")\s?([kKmMgG])?\s?"
    r"(TiB|GiB|MiB|KiB|TB|GB|MB|KB|B|bytes?|tokens?|requests?|sessions?"
    r"|files?|lines?|calls?|transcripts?|prompts?|turns?|ms)\b")

#: The same nouns, for the "big number NEAR a corpus noun" rule.
_NOUN_RE = re.compile(
    r"\b(bytes?|tokens?|requests?|sessions?|files?|lines?|calls?"
    r"|transcripts?|prompts?|conversations?|rows?|records?)\b")

_MONEY_WORD_RE = re.compile(
    r"\b(cost|costs|spend|spent|bill|billed|dollars?|usd|prices?|charged?"
    r"|budget|burn)\b", re.I)

#: Phrasing that MARKS a number as something observed rather than chosen. This
#: is the rule that catches the class when the number itself looks innocent: a
#: fire count "measured at" something, a file count qualified with "on this
#: machine".
_OBSERVED_RE = re.compile(
    r"(?<![\w_])(measured|on this machine|on the real|this corpus"
    r"|in practice here|i measured|we measured|observed here)(?![\w_])", re.I)

_PCT_RE = re.compile(_N + r"\s?%")

#: A rate is a NUMBER you multiply a percentage by. Where the two sit together
#: the pair is an amount in disguise, which is why this is its own rule.
#:
#: It must be a numeric rate, not the word "rate": "a measured 40.4% false-block
#: rate" is a ratio carrying a finding on its own, which is allowed, and matching
#: the noun makes every such sentence a false positive. What is forbidden is a
#: percentage sitting where a per-unit PRICE can multiply it.
_RATE_NUMBER_RE = re.compile(
    r"[$€£]\s?\d|\d\s?(?:/\s?1k\b|/\s?1,000\b|/\s?M?[Tt]ok\b)"
    r"|per\s+1,?000\s+tokens|per\s+M?[Tt]ok", re.I)

#: An amount immediately followed by one of these is a published list price,
#: not an observation, and is explicitly allowed.
_LIST_PRICE_RE = re.compile(
    r"(/\s?M?[Tt]ok|per\s+M?[Tt]ok|per\s+million|/\s?1M|list price)", re.I)

#: Text that must be blanked before any number rule runs, because the digits
#: inside it are syntax rather than quantity: ANSI escape sequences and regex
#: repetition quantifiers. Both are named in the canary suite's must-pass set.
_SYNTAX_NOISE = (
    re.compile(r"(?:\\x1b|\\033|\x1b)\[[0-9;?]*[A-Za-z]"),
    re.compile(r"\{\d+(?:,\d+)?\}"),
)

#: Numbers that only ever appear as the anchors of a units-conversion table.
#: A corpus total is never exactly one of these, and excluding them by RULE is
#: better than three allowlist entries that each say the same thing.
_CONVERSION_ANCHORS = frozenset({1.0, 1000.0, 1024.0})

#: Below this, an integer with a unit is a design constant, not a measurement
#: -- a divisor, a floor, a minimum size. A decimal point, a thousands
#: separator or a magnitude suffix overrides it: a sub-millisecond timing and
#: a thousands-of-lines count are measurements at any magnitude.
_UNIT_FLOOR = 10.0


#: (rule, exact sample) -> why it is not a measurement of anybody's corpus.
#: Reviewed by hand, same contract as PLACEHOLDERS: an entry earns its place by
#: being a number that could not have come from anybody's private data -- a
#: documented default, a product limit, a unit definition, an invented example.
CONTENT_ALLOW: Dict[Tuple[str, str], str] = {
    ("aggregate", "1,000"):
        "unit definition: the carry rate is quoted per 1,000 tokens",
    ("aggregate", "2,000"):
        "Claude Code's own Read truncation limit, a product fact",
    ("aggregate", "2,000 lines"):
        "Claude Code's own Read truncation limit, a product fact",
    ("aggregate", "4,000"):
        "invented round figure illustrating a truncated tool list",
    ("aggregate", "5,000"):
        "invented round figure illustrating an over-long file",
    ("aggregate", "10000"):
        "a `-k` flag value quoted in a comment, not a measurement",
    ("aggregate", "1800"):
        "documented default for idle_exit_seconds",
    ("aggregate", "262144"):
        "documented default for scan.tail_bytes (2^18)",
    ("aggregate", "65536"):
        "documented default for scan.head_bytes (2^16)",
    ("aggregate", "15 bytes"):
        "comm(2) truncates to 15 bytes; a kernel fact",
    ("aggregate", "200000"):
        "the published context window of a model, not a measurement",
    ("currency", "$12.34"):
        "legend placeholder in the dashboard's footer key",
    ("currency", "$1"):
        "invented round figure contrasting a small lever with a large one",
    ("currency", "$500"):
        "invented round figure contrasting a small lever with a large one",
    ("currency", "$10"):
        "display threshold in prose about how many decimals to print",
    ("currency", "$10k"):
        "display threshold in prose about how many decimals to print",
    ("currency", "$0.004"):
        "invented example of a call small enough to still be interesting",
    ("amount", "0.01"):
        "Anthropic's published per-search web_search list price",
    ("amount", "1.23"):
        "invented fixture value in a self-test payload",
    ("amount", "2.72"):
        "invented fixture value in the documented hook payload",
    ("aggregate", "80 ms"):
        "the status-line render budget, enforced by this tool with a deadline "
        "check and a SIGALRM backstop -- a threshold, not a measurement",
    ("aggregate", "80ms"):
        "the same render budget, spelled without a space",
    ("aggregate", "64 MB"):
        "checklist.MIN_FREE_BYTES, the free-disk requirement this tool enforces",
    ("observation",
     "repeat cost        $2.50 calibrated @ $0.126/1k        $0.20 measured "
     "@ $0.0110/1k"):
        "a line of the documentation fixture's captured `oe rereads` output: "
        "'measured' is a COLUMN LABEL, the amounts are the fixture's invented "
        "totals, and the /1k figure is this tool's shipped default rate",
    ("observation",
     "of which avoidable       $2.50 calibrated        $0.20 measured   "
     "(14 calls)"):
        "the same captured block, second summary line, same reasoning",
    ("observation", "measured spend in scope  $4.07"):
        "a line of the documentation fixture's captured `oe savings` output: "
        "'measured spend' is the command's own heading and the total is the "
        "fixture's",
}


# --- tier 4: the LOCAL DENYLIST -- words no rule can guess --------------------
#
# An employer's name, a client's name, a private repository, a source-file
# basename: none of these has a shape. `rows.ts` and `retry.ts` are
# indistinguishable from invented examples, and a proper noun is only a word.
# No regex will ever find them, so the only mechanism that can is a list -- and
# the list is exactly the thing that must not ship.
#
# So it is read from OUTSIDE the tree. $OE_LEAK_DENYLIST, or the default path
# below. Writing the employer's name into the repository in order to detect the
# employer's name would BE the leak, and putting it in a gitignored file inside
# the tree is barely better: `git ls-files --others` would hand it straight back
# to the scanner.
#
# It is therefore machine-local by construction: it does not exist on a CI
# runner, so this tier does NOT run there, and the gate says so out loud rather
# than letting a green result imply a check that never happened.
#
# Format: one term per line, `#` starts a comment, blank lines ignored. Matched
# case-insensitively at word boundaries, so a company name hits its own
# capitalised spelling and the issue key that starts with it, but not a longer
# word that merely begins the same way.
DENYLIST_ENV = "OE_LEAK_DENYLIST"


def denylist_path() -> Optional[Path]:
    """Where the local denylist would be, or None if the location is unusable."""
    override = os.environ.get(DENYLIST_ENV)
    if override:
        return Path(override).expanduser()
    try:
        return Path.home() / ".config" / BUNDLE_NAME / "leak-denylist.txt"
    except Exception:
        return None


def local_denylist() -> Tuple[List[str], Optional[str]]:
    """(terms, where they came from). An empty list means the tier cannot run."""
    path = denylist_path()
    if path is None:
        return [], None
    try:
        raw = path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return [], None
    terms = []
    for line in raw.splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            terms.append(line)
    return terms, str(path) if terms else None


def _denylist_patterns(terms: Sequence[str]) -> List[Tuple[str, "re.Pattern[str]"]]:
    out = []
    for term in terms:
        # \b does not fire next to '.', so a basename needs its own edges: the
        # character before and after must not be a word character.
        out.append((term, re.compile(
            r"(?<![\w])" + re.escape(term) + r"(?![\w])", re.I)))
    return out


def denylist_hits(text: str, terms: Sequence[str]) -> List[Tuple[str, int]]:
    """Every (term, offset) from the local denylist that appears in `text`."""
    hits = []
    for term, pattern in _denylist_patterns(terms):
        for match in pattern.finditer(text):
            hits.append((term, match.start()))
    return sorted(hits, key=lambda pair: pair[1])


@dataclass(frozen=True)
class ContentFinding:
    """One number that may have been measured on somebody's own corpus."""

    rule: str
    sample: str
    line: int
    offset: int
    region: str   # 'prose' (fatal) | 'sample' (a captured output block)
    context: str

    def describe(self) -> str:
        return f"{self.rule}:{self.sample!r} line {self.line}"


def content_allow_reason(rule: str, sample: str) -> Optional[str]:
    """Why this content hit is not a measurement, or None if it is not known."""
    return CONTENT_ALLOW.get((rule, sample))


def _fstring_expressions(chunk: str) -> str:
    """Blank the `{...}` parts of an f-string, keeping its literal text.

    On this Python an f-string is a single STRING token, so its EXPRESSIONS --
    `{n / 1024:,.0f}` -- would otherwise be read as prose containing the
    number 1024. The runtime value is not in the source and is not this tier's
    business; only the literal text around it is.
    """
    out = list(chunk)
    depth = 0
    for i, ch in enumerate(chunk):
        if ch == "{":
            depth += 1
        if depth:
            out[i] = "\n" if ch == "\n" else " "
        if ch == "}" and depth:
            depth -= 1
    return "".join(out)


def _regions(rel: str, text: str) -> List[Tuple[str, int, int]]:
    """Where in `text` prose lives, and which of it is captured output.

    Three shapes:
      *.md          -- fenced blocks are 'sample' (a capture of what the tool
                       printed); everything else is 'prose'.
      Python        -- only COMMENT and STRING tokens are scanned. Scanning
                       code as well would report every `1024` in an arithmetic
                       expression, and the class lives in the words.
      anything else -- the whole file is prose.
    """
    if rel.endswith(".md"):
        spans: List[Tuple[str, int, int]] = []
        fenced = False
        start = off = 0
        for line in text.splitlines(keepends=True):
            if line.lstrip().startswith("```"):
                spans.append(("sample" if fenced else "prose", start, off))
                fenced = not fenced
                start = off
            off += len(line)
        spans.append(("sample" if fenced else "prose", start, off))
        return spans
    try:
        import io
        import tokenize
        line_start = [0]
        for line in text.splitlines(keepends=True):
            line_start.append(line_start[-1] + len(line))
        spans = []
        for tok in tokenize.generate_tokens(io.StringIO(text).readline):
            if tok.type not in (tokenize.COMMENT, tokenize.STRING):
                continue
            begin = line_start[tok.start[0] - 1] + tok.start[1]
            end = line_start[tok.end[0] - 1] + tok.end[1]
            spans.append(("prose", begin, end))
        return spans
    except Exception:
        # Not Python (a shell script, a workflow file) -- scan all of it.
        return [("prose", 0, len(text))]


def _scannable(rel: str, text: str) -> Tuple[str, List[Tuple[str, int, int]]]:
    """`text` with everything outside a scannable region blanked out.

    Offsets and line numbers are preserved, so a finding still points at the
    real place in the real file.
    """
    spans = _regions(rel, text)
    keep = ["\n" if ch == "\n" else " " for ch in text]
    for _, begin, end in spans:
        chunk = text[begin:min(end, len(text))]
        if not rel.endswith(".md") and "{" in chunk:
            chunk = _fstring_expressions(chunk)
        for i, ch in enumerate(chunk):
            keep[begin + i] = ch
    masked = "".join(keep)
    for pattern in _SYNTAX_NOISE:
        masked = pattern.sub(lambda m: " " * len(m.group(0)), masked)
    return masked, spans


def _unit_is_measurement(match: "re.Match[str]") -> bool:
    """True when a `<number><unit>` match is a measurement rather than a knob.

    Below _UNIT_FLOOR an integer with a unit is a design constant, so it is
    only a measurement when a decimal point, a thousands separator or a
    magnitude prefix says it was read off something rather than chosen.
    """
    amount = _value(match.group(1))
    if amount is None or amount == 0 or amount in _CONVERSION_ANCHORS:
        return False
    scaled = bool(match.group(2)) or "." in match.group(1) or "," in match.group(1)
    return scaled or amount >= _UNIT_FLOOR


def _value(raw: str) -> Optional[float]:
    try:
        return float(raw.replace(",", ""))
    except Exception:
        return None


def content_findings(text: str, rel: str) -> List[ContentFinding]:
    """Every number in `rel` that this tier believes was measured."""
    masked, spans = _scannable(rel, text)

    def region_at(offset: int) -> str:
        for kind, begin, end in spans:
            if begin <= offset < end:
                return kind
        return "prose"

    lines = masked.split("\n")
    line_start = [0]
    for line in lines:
        line_start.append(line_start[-1] + len(line) + 1)

    found: Dict[Tuple[str, int, int], ContentFinding] = {}
    for index, line in enumerate(lines):
        base = line_start[index]
        def record(rule: str, sample: str, column: int) -> None:
            key = (rule, index + 1, column)
            if key not in found:
                found[key] = ContentFinding(
                    rule, sample, index + 1, base + column,
                    region_at(base + column), line.strip()[:120])

        def is_pct(end: int) -> bool:
            return line[end:end + 2].lstrip().startswith("%")

        # 1. money with a symbol.
        for match in _CURRENCY_RE.finditer(line):
            amount = _value(match.group(2))
            if not amount:            # `$0`/`$0.00` is a sentinel, not a figure
                continue
            if _LIST_PRICE_RE.search(line[match.end():match.end() + 18]):
                continue
            record("currency", match.group(0).strip(), match.start())

        # 2. money without a symbol: an amount-shaped number beside a money
        #    word. This is the shape a symbol-based rule cannot see.
        for match in _NUM_RE.finditer(line):
            raw = match.group(0)
            amount = _value(raw)
            if amount is None or amount == 0 or is_pct(match.end()):
                continue
            amount_shaped = ("," in raw and "." in raw) or \
                re.fullmatch(r"\d+\.\d{2}", raw)
            if amount_shaped and _MONEY_WORD_RE.search(line):
                record("amount", raw, match.start())

            # 3a. a big number sitting next to a corpus noun.
            if ("," in raw or amount >= 1000) and amount not in _CONVERSION_ANCHORS:
                near = line[max(0, match.start() - 16):match.start()] + \
                    line[match.end():match.end() + 16]
                if _NOUN_RE.search(near):
                    record("aggregate", raw, match.start())

        # 3b. a number with a unit welded to it.
        for match in _UNIT_RE.finditer(line):
            if _unit_is_measurement(match) and not is_pct(match.end()):
                record("aggregate", match.group(0), match.start())

        # 4. phrasing that marks a number as an observation. Requires an
        #    ABSOLUTE beside it: a percentage on its own is explicitly allowed.
        marker = _OBSERVED_RE.search(line)
        if marker:
            absolutes = [("aggregate", m.group(0)) for m in _UNIT_RE.finditer(line)
                         if _unit_is_measurement(m) and not is_pct(m.end())]
            absolutes += [("currency", m.group(0).strip())
                          for m in _CURRENCY_RE.finditer(line)
                          if _value(m.group(2))]
            absolutes += [("aggregate", m.group(0)) for m in _NUM_RE.finditer(line)
                          if (_value(m.group(0)) or 0) >= 10
                          and not is_pct(m.end())]
            # An absolute that is already reviewed is not an observation: the
            # dashboard's legend says "$12.34 ... measured from the transcript"
            # and neither half of that is anybody's data.
            absolutes = [a for a in absolutes if not content_allow_reason(*a)]
            if absolutes:
                record("observation", line.strip()[:100], marker.start())

        # 5. a percentage within reach of a rate: the two multiply back into
        #    an amount even though neither is one.
        window = "\n".join(lines[max(0, index - 2):index + 3])
        pct = _PCT_RE.search(line)
        if pct and _RATE_NUMBER_RE.search(window):
            record("rate-percent", pct.group(0), pct.start())

    return sorted(found.values(), key=lambda f: (f.line, f.offset, f.rule))


#: The two reviewed exemption tables in THIS module. An exemption has to quote
#: the string it exempts, so their literals are the one place in the tree where
#: a forbidden-looking string legitimately appears verbatim -- and scanning them
#: makes a long sample impossible to exempt at all, since only a short one ever
#: exempts itself by accident. Skipping them costs the gate no reach: every
#: string inside them is, by construction, already allowed everywhere. What
#: gates them is the human who reads the reason beside each entry.
_EXEMPTION_TABLES = ("PLACEHOLDERS", "CONTENT_ALLOW")
_EXEMPTION_TABLE_FILE = "oe/package.py"


def exemption_table_lines(text: str, rel: str) -> frozenset:
    """Line numbers occupied by this module's own exemption tables.

    Empty for every other file, and empty when `text` will not parse -- both of
    which leave the tier exactly as strict as it would otherwise be.
    """
    if rel != _EXEMPTION_TABLE_FILE:
        return frozenset()
    try:
        tree = ast.parse(text)
    except Exception:
        return frozenset()
    lines: set = set()
    for node in tree.body:
        targets = []
        if isinstance(node, ast.Assign):
            targets = node.targets
        elif isinstance(node, ast.AnnAssign):
            targets = [node.target]
        for target in targets:
            if isinstance(target, ast.Name) and target.id in _EXEMPTION_TABLES:
                start = node.lineno
                end = getattr(node, "end_lineno", None) or start
                lines.update(range(start, end + 1))
    return frozenset(lines)


def content_leaks(text: str, rel: str) -> Tuple[
        List[ContentFinding], Dict[str, int], List[ContentFinding]]:
    """Split this file's content findings into fatal, allowed, and deferred.

    `deferred` is the honest part: a figure inside a fenced sample-output block
    in docs/ is a capture of what the tool printed, and this tier cannot tell a
    capture of an INVENTED fixture from a capture of a real session. Those are
    counted and printed, never silently dropped, and the reach note says so.

    The OBSERVATION rule stays fatal even inside a sample block, because a line
    that says "measured" claims the figure is real whatever block it is in.
    The RATE-PERCENT rule does not, and that is deliberate: it exists to catch a
    percentage sitting where a per-unit price can multiply it back into an
    amount that is not otherwise written down. Inside a captured block every
    amount IS written down, on the same lines, and is already deferred for the
    undecidability above -- so the percentage reconstructs nothing the deferred
    count has not already reported. Outside a sample block it is fatal as before.
    """
    fatal: List[ContentFinding] = []
    allowed: Dict[str, int] = {}
    deferred: List[ContentFinding] = []
    table_lines = exemption_table_lines(text, rel)
    for finding in content_findings(text, rel):
        if finding.line in table_lines:
            continue
        reason = content_allow_reason(finding.rule, finding.sample)
        if reason:
            allowed[reason] = allowed.get(reason, 0) + 1
            continue
        if finding.region == "sample" and finding.rule != "observation":
            deferred.append(finding)
            continue
        fatal.append(finding)
    return fatal, allowed, deferred


# --- findings ---------------------------------------------------------------


@dataclass
class Leak:
    path: str
    kind: str
    sample: str
    offset: int
    tier: str  # 'identity' | 'shape' | 'content' | 'denylist'

    def line(self) -> str:
        return f"{self.path}  {self.kind}@{self.offset}  {self.sample[:60]!r}"


@dataclass
class Result:
    root: Path
    staged: Path
    files: List[str] = field(default_factory=list)
    leaks: List[Leak] = field(default_factory=list)
    allowed: Dict[str, int] = field(default_factory=dict)
    dropped_config: Dict[str, Any] = field(default_factory=dict)
    skipped: List[str] = field(default_factory=list)
    drift: Dict[str, List[str]] = field(default_factory=dict)
    #: Content-tier hits inside a captured sample-output block. Reported, never
    #: fatal, never silently dropped -- see content_leaks() and the reach note.
    deferred: List[str] = field(default_factory=list)
    #: Where the local denylist came from, or None when tier 4 did not run.
    denylist_source: Optional[str] = None
    archive: Optional[Path] = None
    sha256: str = ""
    bytes: int = 0

    @property
    def ok(self) -> bool:
        return not self.leaks


# --- staging ----------------------------------------------------------------


def _shippable(root: Path) -> Tuple[List[Path], List[str]]:
    """Every file the allowlist admits, plus what it turned away."""
    keep: List[Path] = []
    skipped: List[str] = []
    for name in ROOT_FILES:
        candidate = root / name
        if candidate.is_file():
            keep.append(candidate)
        else:
            skipped.append(f"{name} (absent)")
    for tree, exts in TREES.items():
        base = root / tree
        if not base.is_dir():
            skipped.append(f"{tree}/ (absent)")
            continue
        for found in sorted(base.rglob("*")):
            if not found.is_file() or "__pycache__" in found.parts:
                continue
            if exts is None:
                admitted = "." not in found.name
            else:
                admitted = found.suffix in exts
            if admitted:
                keep.append(found)
            else:
                skipped.append(str(found.relative_to(root)))
    return keep, skipped


def _tildify(value: str) -> str:
    """Absolute home path -> `~/...`, so no default carries a username."""
    try:
        home = str(Path.home())
    except Exception:
        return value
    return "~" + value[len(home):] if home and value.startswith(home) else value


def sanitised_config(root: Path) -> Tuple[str, Dict[str, Any]]:
    """The config that ships, and the local values it refused to carry.

    Ships `paths.DEFAULT_CONFIG` and nothing else. That is the allowlist rule
    applied to settings: a value travels only if it is the code's own default,
    so a tuned `reports_root` pointing at an employer repo -- or an `accounts`
    map holding real addresses -- cannot ride along by being forgotten.
    """
    shipped = json.loads(json.dumps(paths.DEFAULT_CONFIG))
    for key in ("reports_root",):
        if isinstance(shipped.get(key), str):
            shipped[key] = _tildify(shipped[key])
    shipped["accounts"] = {}

    dropped: Dict[str, Any] = {}
    try:
        local = json.loads((root / "config.json").read_text(encoding="utf-8"))
    except Exception:
        local = {}
    if isinstance(local, dict):
        for key in MACHINE_KEYS:
            if key in local and local[key] != shipped.get(key):
                dropped[key] = local[key]
    return json.dumps(shipped, indent=2) + "\n", dropped


def stage(root: Path, dest: Path) -> Result:
    """Copy the allowlisted tree into `dest`, config rewritten to defaults."""
    result = Result(root=root, staged=dest)
    keep, result.skipped = _shippable(root)
    config_text, result.dropped_config = sanitised_config(root)

    for source in keep:
        rel = source.relative_to(root)
        target = dest / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        if rel.as_posix() == "config.json":
            target.write_text(config_text, encoding="utf-8")
        else:
            shutil.copy2(source, target)
        # Executables must stay executable; everything else is data.
        target.chmod(0o755 if os.access(source, os.X_OK) else 0o644)
        result.files.append(rel.as_posix())
    return result


# --- scanning ---------------------------------------------------------------


def _identity_needles() -> List[str]:
    """The real identifiers of this machine, longest first.

    Reaches into redact's private helpers on purpose: they are the single
    definition of "who this machine belongs to", and a second copy here would
    be a second thing to keep in sync.
    """
    needles: List[str] = []
    try:
        needles += list(redact_mod._identity_values())
    except Exception:
        pass
    try:
        needles += list(redact_mod._user_needles())
    except Exception:
        pass
    try:
        needles.append(str(Path.home()))
    except Exception:
        pass
    seen = {n for n in needles if len(str(n)) >= 4}
    return sorted(seen, key=len, reverse=True)


def scan(result: Result) -> Result:
    """Audit the staged tree. Populates `result.leaks`; nothing is fatal here."""
    needles = _identity_needles()
    denied, result.denylist_source = local_denylist()
    lowered = [(n, n.lower()) for n in needles]
    allowed: Dict[str, int] = {}

    # In a checkout, git publishes what git tracks -- not what this allowlist
    # admits. Scanning only the allowlist would let a committed-but-unlisted
    # file through unread, so the two are unioned and the difference reported.
    result.drift = drift(result.root, result.files)
    extra = list(result.drift.get("untracked_by_scan") or [])
    staged = set(result.files)

    for rel in result.files + extra:
        # Allowlisted files were copied into the staging tree; the git-only
        # extras were never staged, so they are read from the checkout.
        path = (result.staged / rel) if rel in staged else (result.root / rel)
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue

        # Tier 1: literal identity. Bare substring, case-insensitive, because
        # '<name>s-laptop' leaks the same name as '<name>'.
        haystack = text.lower()
        for needle, low in lowered:
            at = haystack.find(low)
            while at >= 0:
                if not identity_exempt(rel, text, at):
                    result.leaks.append(Leak(rel, "identity", needle, at, "identity"))
                    break
                # Exempt here, but the same name may appear again further down
                # on a line that is NOT exempt -- keep looking rather than
                # letting one blessed line clear the whole file.
                at = haystack.find(low, at + 1)

        # Tier 2: shape, minus the reviewed placeholders.
        for finding in redact_mod.audit(text, where=rel):
            if finding.severity != "block":
                continue
            # Tier 1 owns these: reporting them again under 'shape' would
            # double every identity leak and make the counts lie.
            if finding.kind in ("identity", "user"):
                continue
            reason = placeholder_reason(finding.kind, finding.sample,
                                        text, finding.offset)
            if reason:
                allowed[reason] = allowed.get(reason, 0) + 1
                continue
            result.leaks.append(
                Leak(rel, finding.kind, finding.sample, finding.offset, "shape"))

        # Tier 3: content. Not a shape at all -- a number that is true about
        # this machine. See the CONTENT tier block above.
        fatal, content_ok, deferred = content_leaks(text, rel)
        for hit in fatal:
            result.leaks.append(
                Leak(rel, hit.rule, hit.sample, hit.offset, "content"))
        for reason, count in content_ok.items():
            allowed[reason] = allowed.get(reason, 0) + count
        for hit in deferred:
            result.deferred.append(f"{rel}:{hit.line}  {hit.rule}  {hit.sample!r}")

        # Tier 4: the local denylist, if this machine has one.
        for term, at in denylist_hits(text, denied):
            result.leaks.append(Leak(rel, "denylist", term, at, "denylist"))

    result.allowed = allowed
    return result


# --- the git checkout, once there is one ---------------------------------------


def git_tracked(root: Path) -> Optional[List[str]]:
    """What git would actually publish, or None if this is not a checkout.

    Once the tool lives in a repo, "what ships" has two definitions -- this
    allowlist and whatever git happens to be tracking -- and the gap between
    them is precisely where a leak hides: a file nobody added to ROOT_FILES is
    still committed, and `oe package` never looks at it. So the packager reads
    git's answer too and reports the difference rather than trusting either
    list alone.
    """
    import subprocess
    try:
        top = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "--show-toplevel"],
            capture_output=True, timeout=30)
    except Exception:
        return None
    if top.returncode != 0:
        return None
    # THE CHECKOUT MUST BE THIS TREE. Run inside somebody else's repository --
    # a tool installed under a dotfiles checkout, a worktree of a monorepo --
    # `git ls-files` exits 0 and lists that repo's answer for this directory,
    # which is usually nothing at all. Returning [] there would read as "a
    # clean checkout tracking no forbidden files", so every git-derived check
    # would pass by asserting nothing. oe/version.py already defends its
    # revision() this way; this is the same guard on the same trap.
    try:
        same = Path(top.stdout.decode("utf-8", "replace").strip()).resolve() \
            == Path(root).resolve()
    except Exception:
        return None
    if not same:
        return None
    try:
        out = subprocess.run(
            ["git", "-C", str(root), "ls-files", "-z", "--cached", "--others",
             "--exclude-standard"],
            capture_output=True, timeout=30)
    except Exception:
        return None
    if out.returncode != 0:
        return None
    return sorted(f for f in out.stdout.decode("utf-8", "replace").split("\0") if f)


def drift(root: Path, shipped: Sequence[str]) -> Dict[str, List[str]]:
    """Files git would publish that the allowlist never scanned, and vice versa.

    `untracked_by_scan` is the dangerous direction: git commits it, the leak
    scan never read it. `unseen_by_git` is usually benign -- a file the
    allowlist admits that is gitignored -- but it is reported too, because it
    means a bundle and a clone would not contain the same tool.

    KNOWN BLIND SPOT: this compares the two lists against EACH OTHER, so a file
    missing from BOTH is invisible here. That is not a leak -- nothing ships it
    either way -- but it is a correctness bug when something in the tree reads
    the file at runtime. VERSION was exactly that: absent from ROOT_FILES and
    denied by .gitignore, so neither a clone nor a bundle carried it and only
    the baked fallback in oe/version.py kept `oe --version` answering. Adding a
    file means naming it in BOTH lists; this function cannot remind you of the
    one you never started.
    """
    tracked = git_tracked(root)
    if tracked is None:
        return {}
    shipped_set = set(shipped)
    return {
        "untracked_by_scan": [f for f in tracked if f not in shipped_set],
        "unseen_by_git": [f for f in shipped_set if f not in set(tracked)],
    }


# --- archive ----------------------------------------------------------------


def _scrub(info: tarfile.TarInfo) -> tarfile.TarInfo:
    """Strip the packager out of the tar HEADERS.

    tar records the owning uid/gid and their NAMES on every member, so a
    bundle whose files are spotless still ships '<packager>/<packager>'
    on every member unless this runs. Times are pinned too, so one tree gives
    one archive and a colleague can diff two bundles meaningfully.
    """
    info.uid = info.gid = 0
    info.uname = info.gname = ""
    info.mtime = 0
    return info


def archive(result: Result, out: Path) -> Result:
    out.parent.mkdir(parents=True, exist_ok=True)
    tmp = out.with_suffix(out.suffix + ".part")
    with tarfile.open(tmp, "w:gz") as tar:
        for rel in sorted(result.files):
            tar.add(result.staged / rel, arcname=f"{BUNDLE_NAME}/{rel}", filter=_scrub)
    tmp.replace(out)
    digest = hashlib.sha256()
    with out.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    result.archive = out
    result.sha256 = digest.hexdigest()
    result.bytes = out.stat().st_size
    return result


def build(root: Optional[Path] = None, out: Optional[Path] = None,
          keep_dir: bool = False) -> Result:
    """Stage, scan, and -- only if the scan is clean -- write the archive.

    The order is the whole point: a bundle cannot exist before it has been
    audited, so there is no window in which a leaky tarball sits on disk
    waiting to be sent.
    """
    root = Path(root or paths.INSTALL_ROOT)
    staging = Path(tempfile.mkdtemp(prefix="oe-package-"))
    keep = False
    try:
        result = scan(stage(root, staging / BUNDLE_NAME))
        if result.ok:
            if out is not None:
                archive(result, Path(out))
            keep = keep_dir
        return result
    finally:
        # Scratch unless the caller asked for the directory form AND the scan
        # passed. A failed scan never leaves a staged copy behind to be picked
        # up by hand later.
        if not keep:
            shutil.rmtree(staging, ignore_errors=True)
