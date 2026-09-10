"""Context store: the data-structure layer the cache/memory enforcement sits on.

One SQLite database (``state_dir()/context.db``) answers three different
questions that the rest of the system asks constantly:

  1. WHAT IS ALREADY IN CONTEXT?  ``covers()`` / ``resident()`` / ``record_read()``
     Residency is tracked as merged line *intervals* scoped to an *epoch*.
     The epoch is the correctness spine: a compaction, a /clear or a fresh
     session destroys the content in the window, so every range recorded
      before it is void and the same Read is legitimate again. Without epochs a
      re-read guard is simply wrong after the first auto-compaction.

  2. WHERE IS THE ANSWER?  ``search()`` / ``subtree()``
     An FTS5 index with native bm25() ranking over symbol-aligned chunks, plus
      an import graph, so a question can be answered with a short slice rather
      than a whole file. That ratio is the entire value proposition: most of the
      bytes a Read returns are a repeat within one context window -- the same
      bytes, paid for twice.

  3. WHAT DID THIS COST?  ``events``
     Every entry into context is journalled with its token cost and, when the
     store avoided one, the tokens it saved.

Design constraints that shaped this file:

  * The read guard calls ``covers()`` inside PreToolUse, before every single
    tool call, so the hot path must be an index seek and nothing else. Ranges
    are kept canonical (disjoint, non-adjacent, sorted) at write time, which
    turns containment into one ``ORDER BY lo DESC LIMIT 1`` probe.
  * A parent session and its subagents write concurrently. WAL + a short
    busy_timeout; readers never block on the writer.
  * Nothing here may take a session down. Every public entry point fails OPEN:
    ``covers()`` returns False (i.e. "not resident, allow the read") on any
    error, a corrupt database is quarantined and rebuilt rather than raised.
    A guard that blocks a legitimate read costs far more than it saves.
  * Stdlib only, and sqlite3 must have FTS5 with native bm25 compiled in;
    `contentless_delete=1` below additionally needs SQLite 3.43 or newer.

Public API (small and stable -- hooks and the CLI depend on exactly this):

    open_db()                                    -> sqlite3.Connection
    current_epoch(session_id)                    -> epoch_id
    new_epoch(session_id, reason)                -> epoch_id
    record_read(session_id, path, lo, hi, bytes, tokens, turn, origin) -> dict
    resident(session_id, path)                   -> dict
    covers(session_id, path, lo, hi)             -> bool
    index_paths(roots, include=, exclude=)       -> dict
    search(query, k)                             -> list[dict]
    subtree(entry, depth, k)                     -> dict
    stats()                                      -> dict
"""

from __future__ import annotations

import json
import os
import re
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

try:  # pragma: no cover - the package is always importable in practice
    from . import paths as _paths
except Exception:  # pragma: no cover - direct-script fallback
    import paths as _paths  # type: ignore


# --------------------------------------------------------------------------
# Constants
# --------------------------------------------------------------------------

SCHEMA_VERSION = 1
DB_NAME = "context.db"

# report.py already prices tool payloads at bytes/4.0; the store must agree with
# it or the two halves of the meter would disagree about the same read.
CHARS_PER_TOKEN = 4.0

# "to end of file" sentinel for a Read with no explicit limit. Chosen to fit an
# INTEGER column and to compare correctly against any real line number.
WHOLE_FILE = 2_147_483_647

# Anything with a NUL in its first block is binary and is never indexed.
_BINARY_SNIFF_BYTES = 8192

DEFAULT_MAX_FILE_BYTES = 1_000_000
DEFAULT_MAX_FILES = 40_000
DEFAULT_BUSY_MS = 2000

MAX_CHUNK_LINES = 140
MIN_CHUNK_LINES = 12
MAX_CHUNK_BYTES = 12_000
MAX_TERMS_PER_CHUNK = 320

DEFAULT_EXCLUDE_DIRS = frozenset({
    ".git", ".hg", ".svn", "node_modules", "dist", "build", "out", "obj", "bin",
    ".next", ".nuxt", ".svelte-kit", ".turbo", ".cache", "coverage", "vendor",
    "__pycache__", ".venv", "venv", "env", ".mypy_cache", ".pytest_cache",
    ".gradle", "target", "packages", "bower_components", ".idea", ".vs",
    "TestResults", ".terraform", ".angular", "storybook-static", ".yarn",
})

DEFAULT_EXCLUDE_GLOBS = (
    "*.min.js", "*.min.css", "*.map", "*.lock", "*-lock.json", "*-lock.yaml",
    "pnpm-lock.yaml", "*.snap", "*.min.*",
    "*.dll", "*.pdb", "*.exe", "*.so", "*.dylib", "*.zip", "*.gz", "*.tgz",
    "*.png", "*.jpg", "*.jpeg", "*.gif", "*.webp", "*.ico", "*.svg", "*.pdf",
    "*.woff", "*.woff2", "*.ttf", "*.eot", "*.mp4", "*.mov", "*.wasm",
    "*.csv", "*.tsv", "*.parquet", "*.db", "*.sqlite", "*.bak",
)

# Extension -> language tag. Only these are indexed; everything else is skipped,
# which is what keeps the index bounded without a size heuristic.
LANGS: Dict[str, str] = {
    ".ts": "ts", ".tsx": "ts", ".mts": "ts", ".cts": "ts",
    ".js": "js", ".jsx": "js", ".mjs": "js", ".cjs": "js",
    ".svelte": "svelte", ".vue": "svelte",
    ".py": "py", ".pyi": "py",
    ".cs": "cs", ".csx": "cs",
    ".sql": "sql",
    ".md": "md", ".mdx": "md", ".markdown": "md",
    ".html": "html", ".htm": "html", ".cshtml": "html", ".liquid": "html",
    ".css": "css", ".scss": "css", ".sass": "css", ".less": "css",
    ".json": "json", ".jsonc": "json",
    ".yml": "yaml", ".yaml": "yaml",
    ".sh": "sh", ".bash": "sh", ".zsh": "sh",
    ".tf": "tf", ".tfvars": "tf",
    ".xml": "xml", ".csproj": "xml", ".config": "xml", ".props": "xml",
}

# Resolution order when an import specifier has no extension.
_RESOLVE_SUFFIXES = (
    "", ".ts", ".tsx", ".d.ts", ".js", ".jsx", ".mjs", ".cjs", ".svelte",
    ".vue", ".py", ".json", ".scss", ".css",
    "/index.ts", "/index.tsx", "/index.js", "/index.jsx", "/index.svelte",
    "/__init__.py", "/index.json",
)


# --------------------------------------------------------------------------
# Small helpers
# --------------------------------------------------------------------------

def estimate_tokens(nbytes: int) -> int:
    """Bytes -> tokens, using the same 4.0 chars/token report.py prices with."""
    try:
        n = int(nbytes)
    except Exception:
        return 0
    if n <= 0:
        return 0
    return max(1, int(n / CHARS_PER_TOKEN + 0.5))


def norm_path(path: Any) -> str:
    """Canonical absolute path. Deliberately abspath and NOT realpath: realpath
    stats every component, and the guard resolves a path on every tool call."""
    try:
        p = os.path.abspath(os.path.expanduser(str(path)))
    except Exception:
        return str(path)
    return p


# Every pattern below is compiled on first use, not at import.
#
# A PreToolUse hook is a fresh process on EVERY tool call, so `import store` is
# on the critical path of the whole session: the module-level re.compile calls
# plus hashlib are a large share of that import, and none of them are reachable
# from covers(), which is all a residency check actually calls. Deferring them
# takes roughly a third off the store's share of a cold call.
_RX: Dict[str, Any] = {}


def _rx() -> Dict[str, Any]:
    if _RX:
        return _RX
    _RX.update({
        "id": re.compile(r"[A-Za-z_][A-Za-z0-9_]{1,63}"),
        "camel": re.compile(r"[A-Z]+(?=[A-Z][a-z])|[A-Z]?[a-z0-9]+|[A-Z]+|[0-9]+"),
        "ts_rules": (
            (re.compile(r"^\s*(export\s+)?(?:default\s+)?(?:declare\s+)?(?:abstract\s+)?class\s+([A-Za-z_$][\w$]*)"), "class"),
            (re.compile(r"^\s*(export\s+)?(?:default\s+)?(?:async\s+)?function\s*\*?\s*([A-Za-z_$][\w$]*)"), "function"),
            (re.compile(r"^\s*(export\s+)?(?:declare\s+)?interface\s+([A-Za-z_$][\w$]*)"), "interface"),
            (re.compile(r"^\s*(export\s+)?(?:declare\s+)?type\s+([A-Za-z_$][\w$]*)\s*[=<]"), "type"),
            (re.compile(r"^\s*(export\s+)?(?:declare\s+)?(?:const\s+)?enum\s+([A-Za-z_$][\w$]*)"), "enum"),
            (re.compile(r"^\s*(export\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::[^=;]{0,120})?=\s*(?:async\s*)?(?:function\b|\(|[A-Za-z_$][\w$]*\s*=>)"), "function"),
            (re.compile(r"^\s*(export\s+)?const\s+([A-Z][A-Z0-9_]{2,})\s*[:=]"), "const"),
        ),
        "ts_method": re.compile(
            r"^\s{1,8}(?:public\s+|private\s+|protected\s+|static\s+|readonly\s+|async\s+|\*\s*)*"
            r"([A-Za-z_$][\w$]*)\s*(?:<[^>()]{0,80}>)?\s*\([^;{]{0,400}\)\s*(?::[^{;]{0,120})?\{"),
        "py_rules": (
            (re.compile(r"^(\s*)(?:async\s+)?def\s+([A-Za-z_]\w*)"), "function"),
            (re.compile(r"^(\s*)class\s+([A-Za-z_]\w*)"), "class"),
        ),
        "cs_type": re.compile(
            r"^\s*(?:\[[^\]]*\]\s*)*(?:(?:public|private|protected|internal|static|sealed|"
            r"abstract|partial|readonly|unsafe|new)\s+)*(class|struct|interface|record|enum)\s+([A-Za-z_]\w*)"),
        "cs_method": re.compile(
            r"^\s*(?:\[[^\]]*\]\s*)*(?:(?:public|private|protected|internal|static|virtual|override|"
            r"async|sealed|extern|unsafe|partial|new|abstract)\s+)+[\w<>\[\],.?]+\s+([A-Za-z_]\w*)\s*\("),
        "cs_ns": re.compile(r"^\s*namespace\s+([\w.]+)"),
        "sql": re.compile(
            r"^\s*CREATE\s+(?:OR\s+ALTER\s+)?(PROCEDURE|PROC|FUNCTION|TABLE|VIEW|TRIGGER|INDEX)\s+"
            r"(\[?[\w.\[\]]+\]?)", re.I),
        "md": re.compile(r"^(#{1,6})\s+(.+?)\s*$"),
        "html_h": re.compile(r"<h([1-6])[^>]*>\s*(.{1,120}?)\s*</h\1>", re.I),
        "html_using": re.compile(r"^\s*@using\s+([\w.]+)"),
        "css_rule": re.compile(r"^([.#&%@][\w\-.#:>\[\]= ]{1,80}|[a-z][\w\-]{1,40}(?:\s*[,{]))\s*\{"),
        "svelte_prop": re.compile(r"^\s*export\s+let\s+([A-Za-z_$][\w$]*)"),
        "imp_ts": re.compile(
            r"""(?:^|\s)(?:import|export)\s+(?:[\w*{}\s,$]*?\s+from\s+)?['"]([^'"]+)['"]"""
            r"""|require\(\s*['"]([^'"]+)['"]\s*\)"""
            r"""|import\(\s*['"]([^'"]+)['"]\s*\)"""),
        "imp_py": re.compile(r"^\s*(?:from\s+([\w.]+)\s+import|import\s+([\w.]+))"),
        "imp_cs": re.compile(r"^\s*(?:global\s+)?using\s+(?:static\s+)?(?:\w+\s*=\s*)?([\w.]+)\s*;"),
        "imp_css": re.compile(r"""^\s*@(?:import|use|forward)\s+['"]([^'"]+)['"]"""),
        "imp_html": re.compile(r"""(?:src|href)\s*=\s*['"]([^'"]+\.(?:js|css|ts|mjs))['"]"""),
        "script_block": re.compile(r"<script[^>]*>(.*?)</script>", re.S | re.I),
        "word": re.compile(r"[A-Za-z0-9_./$-]{2,}"),
    })
    return _RX


def split_identifier(word: str) -> List[str]:
    """`mountLauncher` -> [mountlauncher, mount, launcher]. FTS5's unicode61
    tokenizer glues camelCase into one token, so a query for "launcher" would
    never reach `mountLauncher`; the expansion goes in its own low-weighted
    column instead of polluting the body."""
    low = word.lower()
    out = [low]
    if "_" in word or "-" in word:
        for piece in re.split(r"[_\-]+", low):
            if len(piece) > 1:
                out.append(piece)
    for piece in _rx()["camel"].findall(word):
        pl = piece.lower()
        if len(pl) > 1 and pl != low:
            out.append(pl)
    return out


def _terms_for(text: str, limit: int = MAX_TERMS_PER_CHUNK) -> str:
    seen: Dict[str, None] = {}
    for match in _rx()["id"].finditer(text):
        for piece in split_identifier(match.group(0)):
            if piece not in seen:
                seen[piece] = None
                if len(seen) >= limit:
                    return " ".join(seen)
    return " ".join(seen)


def _fts_query(raw: str) -> str:
    """Turn free text into a safe FTS5 MATCH expression.

    Every term is double-quoted, so `AND`, `OR`, `NOT`, `NEAR`, `-` and `*` in
    user text can never be read as operators and can never raise a syntax
    error inside a hook. Terms are OR-ed and bm25 does the discrimination;
    AND-ing a natural-language question returns nothing most of the time.
    """
    terms: List[str] = []
    seen = set()
    for match in _rx()["word"].finditer(raw or ""):
        word = match.group(0).strip("-./")
        if not word:
            continue
        for piece in split_identifier(word):
            if piece in seen or len(piece) < 2:
                continue
            seen.add(piece)
            terms.append('"%s"' % piece.replace('"', ""))
            if len(piece) >= 4:
                terms.append('"%s"*' % piece.replace('"', ""))
    if not terms:
        return ""
    return " OR ".join(terms[:80])


def _is_binary(blob: bytes) -> bool:
    return b"\x00" in blob[:_BINARY_SNIFF_BYTES]


def _read_text(path: str, max_bytes: int) -> Optional[str]:
    try:
        with open(path, "rb") as handle:
            blob = handle.read(max_bytes + 1)
    except OSError:
        return None
    if len(blob) > max_bytes or _is_binary(blob):
        return None
    try:
        return blob.decode("utf-8")
    except UnicodeDecodeError:
        try:
            return blob.decode("utf-8", "replace")
        except Exception:
            return None


def lang_of(path: str) -> str:
    ext = os.path.splitext(path)[1].lower()
    if path.endswith(".d.ts"):
        return "ts"
    return LANGS.get(ext, "")


# --------------------------------------------------------------------------
# Connection management
# --------------------------------------------------------------------------

_LOCAL = threading.local()


def db_path() -> Path:
    override = os.environ.get("OE_CONTEXT_DB")
    if override:
        return Path(override).expanduser()
    return _paths.state_dir() / DB_NAME


SCHEMA = """
CREATE TABLE IF NOT EXISTS meta(
  key   TEXT PRIMARY KEY,
  value TEXT
);

-- One row per context-reset boundary. Residency below is meaningless outside
-- its epoch, because a compaction/clear physically removes the bytes from the
-- window even though the file on disk never changed.
CREATE TABLE IF NOT EXISTS epochs(
  epoch_id     INTEGER PRIMARY KEY,
  session_id   TEXT    NOT NULL,
  agent_id     TEXT    NOT NULL DEFAULT '',
  reason       TEXT    NOT NULL,
  started_ts   REAL    NOT NULL,
  ended_ts     REAL,
  is_open      INTEGER NOT NULL DEFAULT 1,
  pre_tokens   INTEGER,
  post_tokens  INTEGER,
  note         TEXT
);
CREATE INDEX IF NOT EXISTS epochs_open
  ON epochs(session_id, agent_id, epoch_id DESC) WHERE is_open = 1;
CREATE INDEX IF NOT EXISTS epochs_session ON epochs(session_id, started_ts);

CREATE TABLE IF NOT EXISTS files(
  file_id       INTEGER PRIMARY KEY,
  path          TEXT    NOT NULL UNIQUE,
  lang          TEXT    NOT NULL DEFAULT '',
  size          INTEGER NOT NULL DEFAULT 0,
  mtime_ns      INTEGER NOT NULL DEFAULT 0,
  hash          TEXT    NOT NULL DEFAULT '',
  lines         INTEGER NOT NULL DEFAULT 0,
  tokens        INTEGER NOT NULL DEFAULT 0,
  indexed_ts    REAL,
  root          TEXT    NOT NULL DEFAULT '',
  first_seen_ts REAL,
  first_seen_turn INTEGER,
  read_count    INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS files_root ON files(root);
CREATE INDEX IF NOT EXISTS files_lang ON files(lang);

-- Canonical residency: intervals are disjoint and non-adjacent within an
-- (epoch, file), maintained by merge-on-insert. That invariant is what makes
-- covers() a single index seek instead of an interval scan.
CREATE TABLE IF NOT EXISTS ranges(
  epoch_id   INTEGER NOT NULL,
  file_id    INTEGER NOT NULL,
  lo         INTEGER NOT NULL,
  hi         INTEGER NOT NULL,
  tokens     INTEGER NOT NULL DEFAULT 0,
  bytes      INTEGER NOT NULL DEFAULT 0,
  reads      INTEGER NOT NULL DEFAULT 1,
  first_turn INTEGER,
  first_ts   REAL,
  last_ts    REAL,
  PRIMARY KEY(epoch_id, file_id, lo)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS ranges_file ON ranges(file_id, epoch_id);

CREATE TABLE IF NOT EXISTS symbols(
  symbol_id INTEGER PRIMARY KEY,
  file_id   INTEGER NOT NULL,
  name      TEXT    NOT NULL,
  kind      TEXT    NOT NULL,
  lo        INTEGER NOT NULL,
  hi        INTEGER NOT NULL,
  tokens    INTEGER NOT NULL DEFAULT 0,
  exported  INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS symbols_name ON symbols(name);
CREATE INDEX IF NOT EXISTS symbols_file ON symbols(file_id, lo);

-- Namespaces/modules a file DECLARES, so `using Acme.Billing;` and
-- `from oe.store import x` resolve to a file the same way a relative import does.
CREATE TABLE IF NOT EXISTS provides(
  file_id INTEGER NOT NULL,
  name    TEXT    NOT NULL,
  PRIMARY KEY(file_id, name)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS provides_name ON provides(name);

CREATE TABLE IF NOT EXISTS edges(
  src_file INTEGER NOT NULL,
  raw      TEXT    NOT NULL,
  kind     TEXT    NOT NULL,
  dst_file INTEGER,
  line     INTEGER,
  PRIMARY KEY(src_file, raw, kind)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS edges_dst ON edges(dst_file, src_file);

-- Side table for the FTS rows: rowid is shared with `chunks`.
CREATE TABLE IF NOT EXISTS chunk_meta(
  rowid    INTEGER PRIMARY KEY,
  file_id  INTEGER NOT NULL,
  lo       INTEGER NOT NULL,
  hi       INTEGER NOT NULL,
  tokens   INTEGER NOT NULL DEFAULT 0,
  kind     TEXT    NOT NULL DEFAULT '',
  symbol   TEXT    NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS chunk_meta_file ON chunk_meta(file_id, lo);

CREATE TABLE IF NOT EXISTS events(
  event_id     INTEGER PRIMARY KEY,
  epoch_id     INTEGER NOT NULL,
  ts           REAL    NOT NULL,
  session_id   TEXT    NOT NULL DEFAULT '',
  agent_id     TEXT    NOT NULL DEFAULT '',
  turn         INTEGER,
  kind         TEXT    NOT NULL,
  file_id      INTEGER,
  lo           INTEGER,
  hi           INTEGER,
  bytes        INTEGER NOT NULL DEFAULT 0,
  tokens       INTEGER NOT NULL DEFAULT 0,
  dup_tokens   INTEGER NOT NULL DEFAULT 0,
  saved_tokens INTEGER NOT NULL DEFAULT 0,
  origin       TEXT    NOT NULL DEFAULT '',
  detail       TEXT
);
CREATE INDEX IF NOT EXISTS events_epoch ON events(epoch_id, ts);
CREATE INDEX IF NOT EXISTS events_kind  ON events(kind, ts);
CREATE INDEX IF NOT EXISTS events_sess  ON events(session_id, ts);
"""

# contentless (content='') so the source text is NOT copied into the database --
# only the inverted index is kept, which takes the on-disk size down by roughly
# two thirds. contentless_delete=1 (SQLite >= 3.43) is what keeps incremental
# re-indexing possible without it: a plain contentless table cannot DELETE a
# row, so a changed file could never be re-chunked.
# The consequence is that snippet()/highlight() are unavailable, which is fine
# and arguably better: snippets are cut from the file on disk, so they can never
# show text that an edit has already invalidated.
FTS_SCHEMA = """
CREATE VIRTUAL TABLE IF NOT EXISTS chunks USING fts5(
  path, symbol, heading, body, terms,
  content = '', contentless_delete = 1,
  tokenize = 'unicode61 remove_diacritics 2'
);
"""


class StoreError(RuntimeError):
    pass


def _apply_pragmas(conn: sqlite3.Connection, busy_ms: int) -> None:
    conn.execute("PRAGMA busy_timeout=%d" % int(busy_ms))
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA temp_store=MEMORY")
    conn.execute("PRAGMA cache_size=-8000")
    try:
        conn.execute("PRAGMA mmap_size=268435456")
    except sqlite3.Error:
        pass


def _ensure_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(SCHEMA)
    try:
        conn.executescript(FTS_SCHEMA)
    except sqlite3.OperationalError:
        # No FTS5 in this build: search() degrades to LIKE, everything else
        # keeps working. Never fatal.
        pass
    row = conn.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()
    have = int(row[0]) if row and str(row[0]).isdigit() else 0
    if have != SCHEMA_VERSION:
        if have:
            # Derived data only -- an index is always cheaper to rebuild than to
            # migrate, and residency is scoped to live sessions anyway.
            for stmt in ("DELETE FROM chunks", "DELETE FROM chunk_meta",
                         "DELETE FROM symbols", "DELETE FROM edges",
                         "DELETE FROM provides", "DELETE FROM files"):
                try:
                    conn.execute(stmt)
                except sqlite3.Error:
                    pass
        conn.execute("INSERT OR REPLACE INTO meta(key,value) VALUES('schema_version',?)",
                     (str(SCHEMA_VERSION),))
    conn.commit()


# SQLite reports a genuinely-broken FILE and a merely-hostile ENVIRONMENT through
# the same exception base, and only the first one may ever be "healed" by moving
# the user's data aside.
#
#   corruption   -> sqlite3.DatabaseError   "file is not a database"
#                                           "database disk image is malformed"
#   environment  -> sqlite3.OperationalError (a DatabaseError SUBCLASS)
#                                           "unable to open database file"
#                                           "disk I/O error"
#                                           "database or disk is full"
#                                           "attempt to write a readonly database"
#
# Catching the BASE class here is the trap: a FULL DISK then renames a perfectly
# healthy store to `context.db.corrupt-<stamp>` and drops an empty one in its
# place -- silently, on a hook that can run before every tool call. `ulimit -f 0`
# reproduces it in one command. The same shape covers a read-only mount, a
# revoked permission and a full quota. Anything not on this list propagates
# instead: the caller then fails open with NO database, which costs a residency
# check its answer for one process and costs the user nothing at all.
_CORRUPTION_MARKERS = ("not a database", "malformed", "encrypted",
                       "corrupt", "unsupported file format",
                       "unrecognized token")


def _is_corruption(exc: BaseException) -> bool:
    """Does this error mean the FILE is bad (vs. the disk/permissions)?"""
    try:
        return any(marker in str(exc).lower() for marker in _CORRUPTION_MARKERS)
    except Exception:
        return False


def _quarantine(path: Path) -> None:
    """Move a corrupt database aside so the next open builds a clean one.

    Regular files ONLY, and that guard is not theoretical. sqlite3.connect() on a
    path that is a DIRECTORY raises OperationalError -- a DatabaseError -- which
    open_db() reads as "corrupt". Without this check the recovery below would
    rename that whole directory to `<name>.corrupt-<stamp>` and drop a fresh
    database where it had been. That is recoverable (a rename, not a delete) but
    a tool on the tool-call path must not relocate a user's directory because an
    env var pointed somewhere unexpected. Anything that is not a regular file is
    left exactly where it is, and open_db() then reports the failure instead of
    "fixing" it.
    """
    stamp = time.strftime("%Y%m%d-%H%M%S")
    for suffix in ("", "-wal", "-shm"):
        victim = Path(str(path) + suffix)
        try:
            if not victim.is_file():          # missing, a directory, a socket, ...
                continue
            victim.rename(Path(str(path) + suffix + ".corrupt-" + stamp))
        except OSError:
            try:
                if victim.is_file():
                    victim.unlink()
            except OSError:
                pass


def open_db(path: Optional[os.PathLike] = None, *, busy_ms: int = DEFAULT_BUSY_MS,
            fresh: bool = False) -> sqlite3.Connection:
    """Open (and if needed create or repair) the context database.

    Self-healing, but only for the one failure that self-healing can fix: a
    CORRUPT file (see _is_corruption) is renamed aside and rebuilt once, so a
    caller never sees a broken database -- at worst an empty one. An
    environmental failure (full disk, read-only mount, no permission) is
    re-raised untouched, because renaming the store would destroy history to
    "fix" a problem that was never in the store.
    """
    target = Path(path) if path is not None else db_path()
    key = str(target)
    if not fresh:
        cache = getattr(_LOCAL, "conns", None)
        if cache is None:
            cache = _LOCAL.conns = {}
        entry = cache.get(key)
        if entry is not None:
            conn, ino = entry
            try:
                conn.execute("SELECT 1").fetchone()
                # A quarantine (or an external rm) renames the file out from
                # under an open handle. SQLite keeps happily writing to the
                # orphaned inode, so a long-lived holder -- the watcher -- would
                # silently lose everything it wrote after a heal. Comparing the
                # inode costs one stat against a full open.
                if os.stat(key).st_ino == ino:
                    return conn
            except (sqlite3.Error, OSError):
                pass
            try:
                conn.close()
            except sqlite3.Error:
                pass
            cache.pop(key, None)

    for attempt in (0, 1):
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            conn = sqlite3.connect(key, timeout=busy_ms / 1000.0,
                                   isolation_level=None, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            _apply_pragmas(conn, busy_ms)
            _ensure_schema(conn)
            if not fresh:
                try:
                    ino = os.stat(key).st_ino
                except OSError:
                    ino = 0
                _LOCAL.conns[key] = (conn, ino)  # type: ignore[attr-defined]
            return conn
        except sqlite3.DatabaseError as exc:
            # Only a bad FILE earns a quarantine. See _is_corruption(): a full
            # disk, a read-only mount and a revoked permission all raise here
            # too, and healing those means deleting history to fix a problem
            # that is not in the database.
            if attempt == 0 and _is_corruption(exc):
                _quarantine(target)
                continue
            raise
    raise StoreError("unreachable")


def close_all() -> None:
    cache = getattr(_LOCAL, "conns", None) or {}
    for conn, _ino in list(cache.values()):
        try:
            conn.close()
        except sqlite3.Error:
            pass
    cache.clear()


def _conn(conn: Optional[sqlite3.Connection]) -> sqlite3.Connection:
    return conn if conn is not None else open_db()


# --------------------------------------------------------------------------
# Epochs
# --------------------------------------------------------------------------

def new_epoch(session_id: str, reason: str = "startup", *, agent_id: str = "",
              pre_tokens: Optional[int] = None, post_tokens: Optional[int] = None,
              note: str = "", conn: Optional[sqlite3.Connection] = None) -> int:
    """Close whatever epoch was open for this (session, agent) and start a new
    one. Called on SessionStart, PostCompact and /clear."""
    try:
        cx = _conn(conn)
        now = time.time()
        sid = str(session_id or "unknown")
        aid = str(agent_id or "")
        cx.execute("BEGIN IMMEDIATE")
        cx.execute(
            "UPDATE epochs SET is_open=0, ended_ts=?, post_tokens=COALESCE(?,post_tokens) "
            "WHERE session_id=? AND agent_id=? AND is_open=1",
            (now, post_tokens, sid, aid))
        cur = cx.execute(
            "INSERT INTO epochs(session_id,agent_id,reason,started_ts,is_open,pre_tokens,note) "
            "VALUES(?,?,?,?,1,?,?)",
            (sid, aid, str(reason or "startup"), now, pre_tokens, str(note or "")))
        epoch_id = int(cur.lastrowid)
        cx.execute("COMMIT")
        return epoch_id
    except Exception:
        try:
            cx.execute("ROLLBACK")
        except Exception:
            pass
        return 0


def current_epoch(session_id: str, *, agent_id: str = "", create: bool = True,
                  conn: Optional[sqlite3.Connection] = None) -> int:
    """The open epoch for this (session, agent), creating one if absent.

    Subagents carry their own agent_id and therefore their own residency: the
    parent having read a file says nothing about what is in a subagent's window.
    """
    try:
        cx = _conn(conn)
        sid = str(session_id or "unknown")
        aid = str(agent_id or "")
        row = cx.execute(
            "SELECT epoch_id FROM epochs WHERE session_id=? AND agent_id=? AND is_open=1 "
            "ORDER BY epoch_id DESC LIMIT 1", (sid, aid)).fetchone()
        if row:
            return int(row[0])
        if not create:
            return 0
        return new_epoch(sid, "startup", agent_id=aid, conn=cx)
    except Exception:
        return 0


def epoch_info(epoch_id: int, *, conn: Optional[sqlite3.Connection] = None) -> Dict[str, Any]:
    try:
        cx = _conn(conn)
        row = cx.execute("SELECT * FROM epochs WHERE epoch_id=?", (int(epoch_id),)).fetchone()
        return dict(row) if row else {}
    except Exception:
        return {}


# --------------------------------------------------------------------------
# Files
# --------------------------------------------------------------------------

def _file_id(cx: sqlite3.Connection, path: str, *, create: bool = False,
             turn: Optional[int] = None) -> int:
    row = cx.execute("SELECT file_id FROM files WHERE path=?", (path,)).fetchone()
    if row:
        return int(row[0])
    if not create:
        return 0
    try:
        st = os.stat(path)
        size, mtime_ns = st.st_size, st.st_mtime_ns
    except OSError:
        size, mtime_ns = 0, 0
    cur = cx.execute(
        "INSERT OR IGNORE INTO files(path,lang,size,mtime_ns,tokens,first_seen_ts,first_seen_turn) "
        "VALUES(?,?,?,?,?,?,?)",
        (path, lang_of(path), size, mtime_ns, estimate_tokens(size), time.time(), turn))
    if cur.lastrowid:
        return int(cur.lastrowid)
    row = cx.execute("SELECT file_id FROM files WHERE path=?", (path,)).fetchone()
    return int(row[0]) if row else 0


def file_info(path: str, *, conn: Optional[sqlite3.Connection] = None) -> Dict[str, Any]:
    try:
        cx = _conn(conn)
        row = cx.execute("SELECT * FROM files WHERE path=?", (norm_path(path),)).fetchone()
        return dict(row) if row else {}
    except Exception:
        return {}


# --------------------------------------------------------------------------
# Residency: record_read / resident / covers
# --------------------------------------------------------------------------

def _normalize_span(line_start: Any, line_end: Any) -> Tuple[int, int]:
    try:
        lo = int(line_start) if line_start is not None else 1
    except Exception:
        lo = 1
    try:
        hi = int(line_end) if line_end is not None else WHOLE_FILE
    except Exception:
        hi = WHOLE_FILE
    if lo < 1:
        lo = 1
    if hi < lo:
        hi = lo
    if hi > WHOLE_FILE:
        hi = WHOLE_FILE
    return lo, hi


def covers(session_id: str, path: str, line_start: Any = None, line_end: Any = None,
           *, agent_id: str = "", conn: Optional[sqlite3.Connection] = None) -> bool:
    """Is [line_start, line_end] ALREADY resident in this epoch's context?

    Hot path -- the read guard calls this before every Read. One index seek:
    because intervals are canonical, the single interval with the greatest
    ``lo <= line_start`` is the only one that can contain the query.

    FAILS OPEN: any error returns False, meaning "not resident", meaning the
    guard lets the read through.
    """
    try:
        cx = _conn(conn)
        epoch = current_epoch(session_id, agent_id=agent_id, create=False, conn=cx)
        if not epoch:
            return False
        fid = _file_id(cx, norm_path(path))
        if not fid:
            return False
        lo, hi = _normalize_span(line_start, line_end)
        row = cx.execute(
            "SELECT hi FROM ranges WHERE epoch_id=? AND file_id=? AND lo<=? "
            "ORDER BY lo DESC LIMIT 1", (epoch, fid, lo)).fetchone()
        return bool(row) and int(row[0]) >= hi
    except Exception:
        return False


def resident(session_id: str, path: str, *, agent_id: str = "",
             conn: Optional[sqlite3.Connection] = None) -> Dict[str, Any]:
    """Merged residency for one file in the current epoch."""
    empty = {"path": norm_path(path), "epoch_id": 0, "ranges": [], "tokens": 0,
             "bytes": 0, "reads": 0, "first_turn": None, "first_ts": None,
             "whole_file": False}
    try:
        cx = _conn(conn)
        epoch = current_epoch(session_id, agent_id=agent_id, create=False, conn=cx)
        if not epoch:
            return empty
        fid = _file_id(cx, norm_path(path))
        if not fid:
            return empty
        rows = cx.execute(
            "SELECT lo,hi,tokens,bytes,reads,first_turn,first_ts,last_ts FROM ranges "
            "WHERE epoch_id=? AND file_id=? ORDER BY lo", (epoch, fid)).fetchall()
        if not rows:
            return empty
        spans = [(int(r["lo"]), int(r["hi"])) for r in rows]
        turns = [r["first_turn"] for r in rows if r["first_turn"] is not None]
        times = [r["first_ts"] for r in rows if r["first_ts"] is not None]
        return {
            "path": norm_path(path),
            "epoch_id": epoch,
            "ranges": spans,
            "tokens": sum(int(r["tokens"]) for r in rows),
            "bytes": sum(int(r["bytes"]) for r in rows),
            "reads": sum(int(r["reads"]) for r in rows),
            "first_turn": min(turns) if turns else None,
            "first_ts": min(times) if times else None,
            "whole_file": any(lo <= 1 and hi >= WHOLE_FILE for lo, hi in spans),
        }
    except Exception:
        return empty


def _overlap_tokens(cx: sqlite3.Connection, epoch: int, fid: int, lo: int, hi: int,
                    tokens: int) -> Tuple[int, int]:
    """(overlapping lines, tokens attributable to the overlap) for a proposed
    span against what is already resident. This is the re-read measurement."""
    rows = cx.execute(
        "SELECT lo,hi FROM ranges WHERE epoch_id=? AND file_id=? AND lo<=? AND hi>=? ",
        (epoch, fid, hi, lo)).fetchall()
    covered = 0
    for row in rows:
        a, b = max(lo, int(row["lo"])), min(hi, int(row["hi"]))
        if b >= a:
            covered += b - a + 1
    span = hi - lo + 1
    if span <= 0 or covered <= 0:
        return 0, 0
    if covered >= span:
        return span, int(tokens)
    return covered, int(tokens * (covered / float(span)))


def record_read(session_id: str, path: str, line_start: Any = None,
                line_end: Any = None, bytes_: int = 0, tokens: Optional[int] = None,
                turn: Optional[int] = None, origin: str = "Read", *,
                agent_id: str = "", detail: Any = None,
                saved_tokens: int = 0, kind: str = "read",
                conn: Optional[sqlite3.Connection] = None) -> Dict[str, Any]:
    """Record that [line_start, line_end] of `path` entered context.

    Merges into the canonical interval set (overlapping AND adjacent spans
    collapse), journals an event, and returns what the caller needs to report:
    how much of this read was already resident.
    """
    out = {"ok": False, "epoch_id": 0, "file_id": 0, "duplicate": False,
           "dup_lines": 0, "dup_tokens": 0, "tokens": 0, "merged": None}
    cx = None
    try:
        cx = _conn(conn)
        target = norm_path(path)
        epoch = current_epoch(session_id, agent_id=agent_id, conn=cx)
        if not epoch:
            return out
        lo, hi = _normalize_span(line_start, line_end)
        nbytes = int(bytes_ or 0)
        ntok = int(tokens) if tokens is not None else estimate_tokens(nbytes)
        now = time.time()

        cx.execute("BEGIN IMMEDIATE")
        fid = _file_id(cx, target, create=True, turn=turn)
        if not fid:
            cx.execute("ROLLBACK")
            return out

        dup_lines, dup_tokens = _overlap_tokens(cx, epoch, fid, lo, hi, ntok)

        # Collapse every interval that overlaps or merely touches [lo-1, hi+1].
        neighbours = cx.execute(
            "SELECT lo,hi,tokens,bytes,reads,first_turn,first_ts FROM ranges "
            "WHERE epoch_id=? AND file_id=? AND lo<=? AND hi>=?",
            (epoch, fid, min(WHOLE_FILE, hi + 1), max(1, lo - 1))).fetchall()
        mlo, mhi = lo, hi
        mtok, mbytes, mreads = ntok, nbytes, 1
        mturn = turn
        mts = now
        for row in neighbours:
            mlo = min(mlo, int(row["lo"]))
            mhi = max(mhi, int(row["hi"]))
            mtok += int(row["tokens"])
            mbytes += int(row["bytes"])
            mreads += int(row["reads"])
            if row["first_turn"] is not None:
                mturn = row["first_turn"] if mturn is None else min(mturn, int(row["first_turn"]))
            if row["first_ts"] is not None:
                mts = min(mts, float(row["first_ts"]))
        if neighbours:
            cx.execute(
                "DELETE FROM ranges WHERE epoch_id=? AND file_id=? AND lo<=? AND hi>=?",
                (epoch, fid, min(WHOLE_FILE, hi + 1), max(1, lo - 1)))
        cx.execute(
            "INSERT INTO ranges(epoch_id,file_id,lo,hi,tokens,bytes,reads,first_turn,first_ts,last_ts)"
            " VALUES(?,?,?,?,?,?,?,?,?,?)",
            (epoch, fid, mlo, mhi, mtok, mbytes, mreads, mturn, mts, now))
        cx.execute("UPDATE files SET read_count=read_count+1 WHERE file_id=?", (fid,))
        cx.execute(
            "INSERT INTO events(epoch_id,ts,session_id,agent_id,turn,kind,file_id,lo,hi,"
            "bytes,tokens,dup_tokens,saved_tokens,origin,detail) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (epoch, now, str(session_id or "unknown"), str(agent_id or ""), turn,
             str(kind or "read"), fid, lo, hi, nbytes, ntok, dup_tokens,
             int(saved_tokens or 0), str(origin or ""),
             json.dumps(detail, separators=(",", ":")) if detail is not None else None))
        cx.execute("COMMIT")

        out.update({"ok": True, "epoch_id": epoch, "file_id": fid,
                    "duplicate": dup_lines > 0, "dup_lines": dup_lines,
                    "dup_tokens": dup_tokens, "tokens": ntok,
                    "merged": (mlo, mhi)})
        return out
    except Exception:
        try:
            if cx is not None:
                cx.execute("ROLLBACK")
        except Exception:
            pass
        return out


def record_event(session_id: str, kind: str, *, agent_id: str = "", turn: Any = None,
                 path: str = "", tokens: int = 0, bytes_: int = 0,
                 saved_tokens: int = 0, origin: str = "", detail: Any = None,
                 conn: Optional[sqlite3.Connection] = None) -> bool:
    """Journal a non-read context event (a guard denial, a served slice, a
    compaction). Feeds the money reporting; never raises."""
    try:
        cx = _conn(conn)
        epoch = current_epoch(session_id, agent_id=agent_id, conn=cx)
        fid = _file_id(cx, norm_path(path), create=True) if path else None
        cx.execute(
            "INSERT INTO events(epoch_id,ts,session_id,agent_id,turn,kind,file_id,"
            "bytes,tokens,saved_tokens,origin,detail) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            (epoch, time.time(), str(session_id or "unknown"), str(agent_id or ""),
             turn, str(kind), fid, int(bytes_ or 0), int(tokens or 0),
             int(saved_tokens or 0), str(origin or ""),
             json.dumps(detail, separators=(",", ":")) if detail is not None else None))
        return True
    except Exception:
        return False


def epoch_residency(session_id: str, *, agent_id: str = "", limit: int = 200,
                    conn: Optional[sqlite3.Connection] = None) -> List[Dict[str, Any]]:
    """Everything resident in the current epoch, heaviest first. Drives the
    'what is my window actually full of' report."""
    try:
        cx = _conn(conn)
        epoch = current_epoch(session_id, agent_id=agent_id, create=False, conn=cx)
        if not epoch:
            return []
        rows = cx.execute(
            "SELECT f.path AS path, SUM(r.tokens) AS tokens, SUM(r.bytes) AS bytes, "
            "SUM(r.reads) AS reads, MIN(r.first_turn) AS first_turn, COUNT(*) AS spans "
            "FROM ranges r JOIN files f USING(file_id) WHERE r.epoch_id=? "
            "GROUP BY f.file_id ORDER BY tokens DESC LIMIT ?", (epoch, int(limit))).fetchall()
        return [dict(r) for r in rows]
    except Exception:
        return []


# --------------------------------------------------------------------------
# Language scanners (regex, deliberately cheap and language-agnostic)
# --------------------------------------------------------------------------

_KEYWORDS = frozenset({
    "if", "for", "while", "switch", "catch", "return", "function", "do", "else",
    "try", "with", "case", "new", "typeof", "await", "yield", "using", "lock",
    "foreach", "get", "set", "class", "struct", "record", "namespace", "public",
    "private", "protected", "internal", "static", "var", "let", "const",
})




def scan_file(text: str, lang: str) -> Dict[str, Any]:
    """Extract symbols, provided module names and import specifiers.

    A symbol's span runs to the line before the next symbol start at the same or
    shallower indentation -- language-agnostic, one pass, and accurate enough to
    slice on. Brace/индent tracking was deliberately not attempted: it costs
    more than it buys for chunk boundaries.
    """
    RX = _rx()
    lines = text.split("\n")
    # A trailing newline TERMINATES the last line, it does not begin another, so
    # split("\n") hands back one empty element too many. That extra line is not
    # cosmetic: files.lines is what a whole-file claim is clamped to, so an
    # inflated count makes covers(1, real+1) False for every newline-terminated
    # file -- which is nearly all of them -- and a residency check could never
    # deny the whole-file re-read it exists to stop.
    n = len(lines)
    if n and lines[-1] == "":
        n -= 1
    syms: List[Dict[str, Any]] = []
    provides: List[str] = []
    imports: List[Tuple[str, str, int]] = []

    def add(name: str, kind: str, idx: int, indent: int, exported: int = 0) -> None:
        if not name or name in _KEYWORDS:
            return
        syms.append({"name": name, "kind": kind, "lo": idx + 1,
                     "indent": indent, "exported": exported})

    if lang in ("ts", "js", "svelte"):
        scan_ranges: List[Tuple[int, int]] = [(0, n)]
        if lang == "svelte":
            scan_ranges = []
            for match in RX["script_block"].finditer(text):
                start = text.count("\n", 0, match.start(1))
                end = text.count("\n", 0, match.end(1)) + 1
                scan_ranges.append((start, min(n, end)))
            if not scan_ranges:
                scan_ranges = [(0, n)]
        for start, end in scan_ranges:
            for idx in range(start, end):
                line = lines[idx]
                if not line or line.lstrip().startswith(("//", "*", "/*")):
                    continue
                indent = len(line) - len(line.lstrip())
                hit = False
                for rule, kind in RX["ts_rules"]:
                    match = rule.match(line)
                    if match:
                        add(match.group(2), kind, idx, indent, 1 if match.group(1) else 0)
                        hit = True
                        break
                if hit:
                    continue
                if lang == "svelte":
                    match = RX["svelte_prop"].match(line)
                    if match:
                        add(match.group(1), "prop", idx, indent, 1)
                        continue
                match = RX["ts_method"].match(line)
                if match and match.group(1) not in _KEYWORDS:
                    add(match.group(1), "method", idx, indent)
        for idx, line in enumerate(lines):
            if "import" not in line and "require" not in line and "from" not in line:
                continue
            for match in RX["imp_ts"].finditer(line):
                spec = match.group(1) or match.group(2) or match.group(3)
                if spec:
                    imports.append((spec, "import", idx + 1))

    elif lang == "py":
        for idx, line in enumerate(lines):
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            for rule, kind in RX["py_rules"]:
                match = rule.match(line)
                if match:
                    add(match.group(2), kind, idx, len(match.group(1)),
                        0 if match.group(2).startswith("_") else 1)
                    break
            match = RX["imp_py"].match(line)
            if match:
                imports.append(((match.group(1) or match.group(2)), "import", idx + 1))

    elif lang == "cs":
        for idx, line in enumerate(lines):
            stripped = line.lstrip()
            if not stripped or stripped.startswith("//"):
                continue
            indent = len(line) - len(stripped)
            match = RX["cs_ns"].match(line)
            if match:
                provides.append(match.group(1))
                add(match.group(1), "namespace", idx, indent, 1)
                continue
            match = RX["cs_type"].match(line)
            if match:
                add(match.group(2), match.group(1), idx, indent, 1)
                provides.append(match.group(2))
                continue
            match = RX["cs_method"].match(line)
            if match and match.group(1) not in _KEYWORDS:
                add(match.group(1), "method", idx, indent)
                continue
            match = RX["imp_cs"].match(line)
            if match:
                imports.append((match.group(1), "using", idx + 1))

    elif lang == "sql":
        for idx, line in enumerate(lines):
            match = RX["sql"].match(line)
            if match:
                name = match.group(2).replace("[", "").replace("]", "")
                add(name.split(".")[-1], match.group(1).lower(), idx, 0, 1)
                provides.append(name)

    elif lang == "md":
        for idx, line in enumerate(lines):
            match = RX["md"].match(line)
            if match:
                add(match.group(2)[:120], "h%d" % len(match.group(1)), idx,
                    len(match.group(1)), 1)

    elif lang in ("html",):
        for idx, line in enumerate(lines):
            for match in RX["html_h"].finditer(line):
                add(re.sub(r"<[^>]+>", "", match.group(2))[:120], "h" + match.group(1), idx, 0, 1)
            for match in RX["imp_html"].finditer(line):
                imports.append((match.group(1), "asset", idx + 1))
            match = RX["html_using"].match(line)
            if match:
                imports.append((match.group(1), "using", idx + 1))

    elif lang == "css":
        for idx, line in enumerate(lines):
            match = RX["imp_css"].match(line)
            if match:
                imports.append((match.group(1), "import", idx + 1))
                continue
            if line and not line[0].isspace():
                match = RX["css_rule"].match(line)
                if match:
                    add(match.group(1).strip(" ,{")[:80], "rule", idx, 0, 1)

    # Close spans: a symbol runs until the next symbol at the same or lower
    # indentation, capped at the end of file.
    syms.sort(key=lambda s: s["lo"])
    for i, sym in enumerate(syms):
        end = n
        for j in range(i + 1, len(syms)):
            if syms[j]["indent"] <= sym["indent"]:
                end = syms[j]["lo"] - 1
                break
        sym["hi"] = max(sym["lo"], end)
    return {"symbols": syms, "provides": provides, "imports": imports, "lines": n}


# --------------------------------------------------------------------------
# Chunking
# --------------------------------------------------------------------------

def build_chunks(text: str, lang: str, symbols: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Symbol-aligned chunks, windowed so no chunk is unreasonably large.

    Chunk boundaries follow top-level symbol starts where they exist, so a hit
    returns a whole function rather than an arbitrary window. Files with no
    symbols (json, yaml, config) fall back to fixed windows.
    """
    lines = text.split("\n")
    n = len(lines)
    if n == 0:
        return []

    if lang == "md":
        # Heading depth is stored in `indent`, so a min-indent filter would keep
        # only h1 and glue whole documents into one chunk. Every heading splits.
        tops = list(symbols)
    else:
        base = min((x["indent"] for x in symbols), default=0)
        tops = [s for s in symbols if s["indent"] == base]
    starts = sorted({1} | {int(s["lo"]) for s in tops})
    starts = [s for s in starts if 1 <= s <= n]
    if not starts:
        starts = [1]

    regions: List[Tuple[int, int]] = []
    for i, start in enumerate(starts):
        end = (starts[i + 1] - 1) if i + 1 < len(starts) else n
        if end >= start:
            regions.append((start, end))

    # Merge runs of tiny regions (a wall of one-line exports) into one chunk.
    merged: List[Tuple[int, int]] = []
    for lo, hi in regions:
        if merged and (hi - merged[-1][0] + 1) <= MIN_CHUNK_LINES * 3 and \
                (merged[-1][1] - merged[-1][0] + 1) < MIN_CHUNK_LINES:
            merged[-1] = (merged[-1][0], hi)
        else:
            merged.append((lo, hi))

    by_start = {int(s["lo"]): s for s in tops}
    heading = ""
    out: List[Dict[str, Any]] = []
    for lo, hi in merged:
        pos = lo
        while pos <= hi:
            end = min(hi, pos + MAX_CHUNK_LINES - 1)
            body = "\n".join(lines[pos - 1:end])
            if len(body) > MAX_CHUNK_BYTES:
                body = body[:MAX_CHUNK_BYTES]
            sym = by_start.get(lo)
            names = [s["name"] for s in symbols if lo <= s["lo"] <= end][:12]
            if sym and str(sym["kind"]).startswith("h"):
                heading = sym["name"]
            out.append({
                "lo": pos, "hi": end,
                "symbol": " ".join(dict.fromkeys(names)),
                "kind": sym["kind"] if sym else ("window" if not names else "block"),
                "heading": heading,
                "body": body,
                "tokens": estimate_tokens(len(body)),
            })
            pos = end + 1
    return out


# --------------------------------------------------------------------------
# Indexing
# --------------------------------------------------------------------------

def _walk(root: str, exclude_dirs: frozenset, exclude_globs: Sequence[str],
          include_globs: Optional[Sequence[str]], max_bytes: int,
          max_files: int) -> Iterable[Tuple[str, int, int]]:
    import fnmatch  # indexing-only; kept off the guard's import path
    count = 0
    for dirpath, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        dirnames[:] = [d for d in dirnames if d not in exclude_dirs and not d.startswith(".claude-")]
        for name in filenames:
            if not lang_of(name):
                continue
            if any(fnmatch.fnmatch(name, pat) for pat in exclude_globs):
                continue
            full = os.path.join(dirpath, name)
            if include_globs and not any(fnmatch.fnmatch(full, pat) for pat in include_globs):
                continue
            try:
                st = os.stat(full)
            except OSError:
                continue
            if not st.st_size or st.st_size > max_bytes:
                continue
            yield full, st.st_size, st.st_mtime_ns
            count += 1
            if count >= max_files:
                return


def index_paths(roots: Sequence[str], include: Optional[Sequence[str]] = None,
                exclude: Optional[Sequence[str]] = None, *,
                max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
                max_files: int = DEFAULT_MAX_FILES,
                full: bool = False, prune: bool = True,
                conn: Optional[sqlite3.Connection] = None) -> Dict[str, Any]:
    """Build or refresh chunks + symbols + edges over `roots`.

    Incremental by (size, mtime_ns) first -- an unchanged file costs one stat
    and one indexed lookup, no read and no hash. Only when the stat differs is
    the content hashed, and only when the hash differs is the file re-parsed
    (a touched-but-identical file is very common after a git operation).
    """
    import hashlib  # indexing-only; kept off the guard's import path
    started = time.time()
    cx = _conn(conn)
    exclude_globs = tuple(exclude) if exclude is not None else DEFAULT_EXCLUDE_GLOBS
    exclude_dirs = DEFAULT_EXCLUDE_DIRS
    stats = {"roots": [], "scanned": 0, "indexed": 0, "unchanged": 0,
             "rehashed": 0, "skipped": 0, "removed": 0, "chunks": 0,
             "symbols": 0, "edges": 0, "bytes": 0}

    known: Dict[str, sqlite3.Row] = {}
    roots_abs = [norm_path(r) for r in roots]
    for root in roots_abs:
        for row in cx.execute("SELECT file_id,path,size,mtime_ns,hash FROM files WHERE root=?",
                              (root,)):
            known[row["path"]] = row

    seen: set = set()
    pending: List[Tuple[str, str, int, int]] = []  # (path, root, size, mtime)

    for root in roots_abs:
        if not os.path.isdir(root):
            continue
        stats["roots"].append(root)
        for fpath, size, mtime_ns in _walk(root, exclude_dirs, exclude_globs, include,
                                           max_file_bytes, max_files):
            stats["scanned"] += 1
            seen.add(fpath)
            prev = known.get(fpath)
            if prev is not None and not full and \
                    int(prev["size"]) == int(size) and int(prev["mtime_ns"]) == int(mtime_ns):
                stats["unchanged"] += 1
                continue
            pending.append((fpath, root, size, mtime_ns))

    for batch_start in range(0, len(pending), 200):
        batch = pending[batch_start:batch_start + 200]
        cx.execute("BEGIN IMMEDIATE")
        try:
            for fpath, root, size, mtime_ns in batch:
                text = _read_text(fpath, max_file_bytes)
                if text is None:
                    stats["skipped"] += 1
                    continue
                digest = hashlib.blake2b(text.encode("utf-8", "replace"),
                                         digest_size=16).hexdigest()
                prev = known.get(fpath)
                if prev is not None and not full and prev["hash"] == digest:
                    # Touched but byte-identical (the usual outcome of a checkout
                    # or a formatter no-op): refresh the stat, skip the parse.
                    cx.execute("UPDATE files SET size=?,mtime_ns=? WHERE file_id=?",
                               (size, mtime_ns, prev["file_id"]))
                    stats["rehashed"] += 1
                    continue
                lang = lang_of(fpath)
                scanned = scan_file(text, lang)
                fid = _index_one(cx, fpath, root, lang, text, size, mtime_ns, digest, scanned)
                if fid:
                    stats["indexed"] += 1
                    stats["bytes"] += size
                    stats["symbols"] += len(scanned["symbols"])
            cx.execute("COMMIT")
        except Exception:
            try:
                cx.execute("ROLLBACK")
            except Exception:
                pass

    if prune:
        stale = [row["file_id"] for path, row in known.items() if path not in seen]
        if stale:
            cx.execute("BEGIN IMMEDIATE")
            try:
                for fid in stale:
                    _purge_file(cx, int(fid))
                    cx.execute("DELETE FROM files WHERE file_id=?", (fid,))
                cx.execute("COMMIT")
                stats["removed"] = len(stale)
            except Exception:
                try:
                    cx.execute("ROLLBACK")
                except Exception:
                    pass

    stats["edges"] = _resolve_edges(cx)
    row = cx.execute("SELECT COUNT(*) FROM chunk_meta").fetchone()
    stats["chunks"] = int(row[0]) if row else 0
    cx.execute("INSERT OR REPLACE INTO meta(key,value) VALUES('last_index',?)",
               (json.dumps({"ts": time.time(), "roots": roots_abs}),))
    try:
        cx.execute("PRAGMA wal_checkpoint(PASSIVE)")
    except sqlite3.Error:
        pass
    stats["seconds"] = round(time.time() - started, 3)
    stats["db_bytes"] = db_bytes()
    return stats


def _purge_file(cx: sqlite3.Connection, file_id: int) -> None:
    cx.execute("DELETE FROM chunks WHERE rowid IN (SELECT rowid FROM chunk_meta WHERE file_id=?)",
               (file_id,))
    cx.execute("DELETE FROM chunk_meta WHERE file_id=?", (file_id,))
    cx.execute("DELETE FROM symbols WHERE file_id=?", (file_id,))
    cx.execute("DELETE FROM edges WHERE src_file=?", (file_id,))
    cx.execute("DELETE FROM provides WHERE file_id=?", (file_id,))


def _index_one(cx: sqlite3.Connection, path: str, root: str, lang: str, text: str,
               size: int, mtime_ns: int, digest: str, scanned: Dict[str, Any]) -> int:
    now = time.time()
    row = cx.execute("SELECT file_id FROM files WHERE path=?", (path,)).fetchone()
    if row:
        fid = int(row[0])
        _purge_file(cx, fid)
        cx.execute(
            "UPDATE files SET lang=?,size=?,mtime_ns=?,hash=?,lines=?,tokens=?,indexed_ts=?,root=? "
            "WHERE file_id=?",
            (lang, size, mtime_ns, digest, scanned["lines"], estimate_tokens(size), now, root, fid))
    else:
        cur = cx.execute(
            "INSERT INTO files(path,lang,size,mtime_ns,hash,lines,tokens,indexed_ts,root) "
            "VALUES(?,?,?,?,?,?,?,?,?)",
            (path, lang, size, mtime_ns, digest, scanned["lines"],
             estimate_tokens(size), now, root))
        fid = int(cur.lastrowid)

    for sym in scanned["symbols"]:
        cx.execute(
            "INSERT INTO symbols(file_id,name,kind,lo,hi,tokens,exported) VALUES(?,?,?,?,?,?,?)",
            (fid, sym["name"][:200], sym["kind"], sym["lo"], sym["hi"], 0, sym.get("exported", 0)))
    for name in dict.fromkeys(scanned["provides"]):
        cx.execute("INSERT OR IGNORE INTO provides(file_id,name) VALUES(?,?)", (fid, name[:200]))
    for spec, kind, line in scanned["imports"]:
        cx.execute("INSERT OR IGNORE INTO edges(src_file,raw,kind,dst_file,line) "
                   "VALUES(?,?,?,NULL,?)", (fid, spec[:400], kind, line))

    rel = path
    for chunk in build_chunks(text, lang, scanned["symbols"]):
        cur = cx.execute(
            "INSERT INTO chunks(path,symbol,heading,body,terms) VALUES(?,?,?,?,?)",
            (rel, chunk["symbol"], chunk["heading"], chunk["body"],
             _terms_for(chunk["body"] + " " + chunk["symbol"] + " " + rel)))
        cx.execute(
            "INSERT INTO chunk_meta(rowid,file_id,lo,hi,tokens,kind,symbol) VALUES(?,?,?,?,?,?,?)",
            (int(cur.lastrowid), fid, chunk["lo"], chunk["hi"], chunk["tokens"],
             chunk["kind"], chunk["symbol"][:200]))
    return fid


def _resolve_edges(cx: sqlite3.Connection) -> int:
    """Second pass: turn import specifiers into file ids.

    Three resolvers, tried in order -- relative path, declared namespace/module
    (`namespace X.Y` for C#, package path for Python), then a longest-suffix
    match that handles aliases like `$lib/...` and `@/...` without parsing a
    tsconfig.
    """
    rows = cx.execute("SELECT file_id,path FROM files").fetchall()
    by_path = {r["path"]: int(r["file_id"]) for r in rows}
    suffix: Dict[str, List[int]] = {}
    for path, fid in by_path.items():
        stem = os.path.splitext(path)[0]
        parts = stem.split(os.sep)
        for depth in (1, 2, 3, 4):
            if len(parts) >= depth:
                key = "/".join(parts[-depth:]).lower()
                suffix.setdefault(key, []).append(fid)
    provides: Dict[str, List[int]] = {}
    for row in cx.execute("SELECT file_id,name FROM provides"):
        provides.setdefault(str(row["name"]).lower(), []).append(int(row["file_id"]))

    resolved = 0
    updates: List[Tuple[int, int, str, str]] = []
    pending = cx.execute(
        "SELECT e.src_file AS src, e.raw AS raw, e.kind AS kind, f.path AS srcpath "
        "FROM edges e JOIN files f ON f.file_id=e.src_file WHERE e.dst_file IS NULL").fetchall()
    for row in pending:
        raw = str(row["raw"])
        dst = 0
        if raw.startswith("."):
            base = os.path.normpath(os.path.join(os.path.dirname(row["srcpath"]), raw))
            for suf in _RESOLVE_SUFFIXES:
                cand = base + suf
                if cand in by_path:
                    dst = by_path[cand]
                    break
        if not dst and row["kind"] in ("using", "import"):
            hits = provides.get(raw.lower())
            if hits and len(hits) <= 4:
                dst = hits[0]
        if not dst:
            token = raw.lstrip("@$~/").replace("\\", "/")
            token = re.sub(r"^(?:src|lib|app)/", "", token)
            token = os.path.splitext(token)[0].lower()
            parts = [p for p in token.split("/") if p and p not in (".", "..")]
            for depth in (4, 3, 2):
                if len(parts) >= depth:
                    hits = suffix.get("/".join(parts[-depth:]))
                    if hits and len(hits) == 1:
                        dst = hits[0]
                        break
            if not dst and len(parts) == 1 and raw.startswith((".", "$", "@", "~", "/")):
                hits = suffix.get(parts[0])
                if hits and len(hits) == 1:
                    dst = hits[0]
        if dst:
            updates.append((dst, int(row["src"]), raw, str(row["kind"])))
    if updates:
        cx.execute("BEGIN IMMEDIATE")
        try:
            cx.executemany("UPDATE edges SET dst_file=? WHERE src_file=? AND raw=? AND kind=?",
                           updates)
            cx.execute("COMMIT")
            resolved = len(updates)
        except Exception:
            try:
                cx.execute("ROLLBACK")
            except Exception:
                pass
    row = cx.execute("SELECT COUNT(*) FROM edges WHERE dst_file IS NOT NULL").fetchone()
    return int(row[0]) if row else resolved


# --------------------------------------------------------------------------
# Retrieval
# --------------------------------------------------------------------------

# path, symbol, heading, body, terms. Symbol and path carry the most signal per
# token; `terms` is the camelCase expansion and must not outrank real prose.
BM25_WEIGHTS = (3.0, 8.0, 4.0, 1.0, 1.5)


def search(query: str, k: int = 8, *, path_glob: str = "", lang: str = "",
           snippet_chars: int = 220,
           conn: Optional[sqlite3.Connection] = None) -> List[Dict[str, Any]]:
    """Rank chunks for `query` with SQLite's native bm25().

    bm25() returns a negative score (more negative = better); it is negated here
    so callers can sort descending like every other ranker.
    """
    try:
        cx = _conn(conn)
        expr = _fts_query(query)
        if not expr:
            return []
        sql = (
            "SELECT c.rowid AS rid, "
            "  bm25(chunks, ?, ?, ?, ?, ?) AS score, "
            "  f.path AS path, "
            "  m.lo AS lo, m.hi AS hi, m.tokens AS tokens, m.kind AS kind, "
            "  m.symbol AS symbol, f.lines AS file_lines, f.tokens AS file_tokens, "
            "  f.lang AS lang "
            "FROM chunks c JOIN chunk_meta m ON m.rowid=c.rowid "
            "JOIN files f ON f.file_id=m.file_id "
            "WHERE chunks MATCH ? ")
        args: List[Any] = list(BM25_WEIGHTS) + [expr]
        if lang:
            sql += "AND f.lang=? "
            args.append(lang)
        if path_glob:
            sql += "AND f.path GLOB ? "
            args.append(path_glob)
        sql += "ORDER BY score LIMIT ?"
        args.append(int(k))
        rows = cx.execute(sql, args).fetchall()
        want = {t.strip('"*') for t in expr.split(" OR ")}
        out = []
        for row in rows:
            hit = {
                "path": row["path"],
                "lo": int(row["lo"]), "hi": int(row["hi"]),
                "score": round(-float(row["score"]), 4),
                "symbol": row["symbol"], "kind": row["kind"], "lang": row["lang"],
                "tokens": int(row["tokens"]),
                "file_lines": int(row["file_lines"] or 0),
                "file_tokens": int(row["file_tokens"] or 0),
                "snippet": "",
            }
            if snippet_chars > 0:
                hit["snippet"] = _snippet(row["path"], int(row["lo"]), int(row["hi"]),
                                          want, snippet_chars)
            out.append(hit)
        return out
    except Exception:
        return []


def _snippet(path: str, lo: int, hi: int, want: set, width: int) -> str:
    """Best-matching line of the chunk, cut from disk.

    snippet() is not available on a contentless FTS table, and going to disk is
    the better trade anyway: the index can be one edit stale, the file cannot.
    """
    try:
        best, best_score = "", -1
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            for idx, line in enumerate(handle, 1):
                if idx < lo:
                    continue
                if idx > hi:
                    break
                low = line.lower()
                score = sum(1 for term in want if term and term in low)
                if score > best_score:
                    best, best_score = line.strip(), score
                    if score == len(want):
                        break
        return " ".join(best.split())[:width]
    except OSError:
        return ""


def file_slice(path: str, lo: int, hi: int, *, max_bytes: int = 200_000) -> str:
    """Read [lo, hi] from disk. Always fresh -- the FTS body may be stale by one
    edit, and a stale slice is worse than a cheap re-read."""
    try:
        out: List[str] = []
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            for idx, line in enumerate(handle, 1):
                if idx < lo:
                    continue
                if idx > hi:
                    break
                out.append(line.rstrip("\n"))
        text = "\n".join(out)
        return text[:max_bytes]
    except OSError:
        return ""


def symbol_lookup(name: str, *, k: int = 20,
                  conn: Optional[sqlite3.Connection] = None) -> List[Dict[str, Any]]:
    try:
        cx = _conn(conn)
        rows = cx.execute(
            "SELECT f.path AS path, s.name AS name, s.kind AS kind, s.lo AS lo, s.hi AS hi, "
            "s.exported AS exported FROM symbols s JOIN files f USING(file_id) "
            "WHERE s.name=? ORDER BY s.exported DESC, (s.hi-s.lo) DESC LIMIT ?",
            (name, int(k))).fetchall()
        return [dict(r) for r in rows]
    except Exception:
        return []


def subtree(entry: str, depth: int = 2, k: int = 40, *, direction: str = "out",
            per_file: int = 3,
            conn: Optional[sqlite3.Connection] = None) -> Dict[str, Any]:
    """Directional dependency closure of `entry`, returned as a ranked slice.

    `direction` is "out" (what entry imports, transitively), "in" (what imports
    entry) or "both". The result is a bounded set of chunks -- header + exported
    symbols per file, shallowest depth first -- rather than a file list, so a
    caller can put the closure into context without reading whole files.

    `per_file` caps how many chunks any single file may contribute. Without it a
    2,000-line entry point spends the whole budget on itself: main.ts alone is
    20 chunks, so k=24 returned 20 chunks of main.ts and 4 of the 33 other files
    in its closure -- a closure view that shows almost no closure.
    """
    out: Dict[str, Any] = {"entry": "", "depth": int(depth), "direction": direction,
                           "files": [], "chunks": [], "tokens": 0,
                           "whole_files_tokens": 0}
    try:
        cx = _conn(conn)
        if not str(entry or "").strip():
            return out
        start = norm_path(entry)
        row = cx.execute("SELECT file_id,path FROM files WHERE path=?", (start,)).fetchone()
        if row is None:
            hits = cx.execute(
                "SELECT file_id,path FROM files WHERE path LIKE ? ORDER BY LENGTH(path) LIMIT 1",
                ("%" + str(entry).lstrip("/"),)).fetchone()
            if hits is None:
                sym = symbol_lookup(str(entry), k=1, conn=cx)
                if not sym:
                    return out
                row = cx.execute("SELECT file_id,path FROM files WHERE path=?",
                                 (sym[0]["path"],)).fetchone()
            else:
                row = hits
        if row is None:
            return out
        root_id, root_path = int(row["file_id"]), row["path"]
        out["entry"] = root_path

        level = {root_id: 0}
        frontier = [root_id]
        for step in range(1, max(0, int(depth)) + 1):
            if not frontier:
                break
            marks = ",".join("?" * len(frontier))
            nxt: List[int] = []
            if direction in ("out", "both"):
                q = ("SELECT DISTINCT dst_file AS n FROM edges WHERE src_file IN (%s) "
                     "AND dst_file IS NOT NULL" % marks)
                nxt += [int(r["n"]) for r in cx.execute(q, frontier)]
            if direction in ("in", "both"):
                q = ("SELECT DISTINCT src_file AS n FROM edges WHERE dst_file IN (%s)" % marks)
                nxt += [int(r["n"]) for r in cx.execute(q, frontier)]
            frontier = []
            for fid in nxt:
                if fid not in level:
                    level[fid] = step
                    frontier.append(fid)
            if len(level) > 400:
                break

        ids = list(level)
        marks = ",".join("?" * len(ids))
        finfo = {int(r["file_id"]): dict(r) for r in cx.execute(
            "SELECT file_id,path,lines,tokens,lang FROM files WHERE file_id IN (%s)" % marks, ids)}
        out["files"] = sorted(
            ({"path": v["path"], "depth": level[fid], "lines": v["lines"],
              "tokens": v["tokens"], "lang": v["lang"]} for fid, v in finfo.items()),
            key=lambda d: (d["depth"], d["path"]))
        out["whole_files_tokens"] = sum(int(v["tokens"] or 0) for v in finfo.values())

        # Rank chunks: shallower first, then declaration-bearing kinds, then the
        # first chunk of a file (its imports/header) which is the cheapest
        # possible orientation for a reader.
        rows = cx.execute(
            "SELECT m.rowid AS rid, m.file_id AS fid, m.lo AS lo, m.hi AS hi, "
            "m.tokens AS tokens, m.kind AS kind, m.symbol AS symbol "
            "FROM chunk_meta m WHERE m.file_id IN (%s) ORDER BY m.file_id, m.lo" % marks,
            ids).fetchall()
        kind_rank = {"class": 0, "interface": 0, "function": 1, "type": 1, "method": 2,
                     "enum": 1, "const": 2, "prop": 2, "block": 3, "window": 4}
        scored = []
        first_seen: set = set()
        for r in rows:
            fid = int(r["fid"])
            is_head = fid not in first_seen
            first_seen.add(fid)
            scored.append((
                level.get(fid, 99),
                0 if is_head else 1,
                kind_rank.get(str(r["kind"]), 5),
                -int(r["tokens"]),
                r))
        # Cap per file BEFORE the global cut, so breadth survives depth.
        if per_file and per_file > 0:
            scored.sort(key=lambda t: (t[4]["fid"], t[1], t[2], t[3]))
            capped, run, last = [], 0, None
            for item in scored:
                fid = int(item[4]["fid"])
                run = run + 1 if fid == last else 1
                last = fid
                if run <= per_file:
                    capped.append(item)
            scored = capped
        scored.sort(key=lambda t: t[:4])
        chunks = []
        total = 0
        for _, _, _, _, r in scored[:max(1, int(k))]:
            fid = int(r["fid"])
            chunks.append({"path": finfo[fid]["path"], "depth": level.get(fid, 99),
                           "lo": int(r["lo"]), "hi": int(r["hi"]),
                           "kind": r["kind"], "symbol": r["symbol"],
                           "tokens": int(r["tokens"])})
            total += int(r["tokens"])
        out["chunks"] = chunks
        out["tokens"] = total
        return out
    except Exception:
        return out


# --------------------------------------------------------------------------
# Stats
# --------------------------------------------------------------------------

def db_bytes() -> int:
    total = 0
    base = db_path()
    for suffix in ("", "-wal", "-shm"):
        try:
            total += os.path.getsize(str(base) + suffix)
        except OSError:
            pass
    return total


def stats(conn: Optional[sqlite3.Connection] = None) -> Dict[str, Any]:
    """Counts and sizes for `oe` commands. Never raises."""
    out: Dict[str, Any] = {"db": str(db_path()), "db_bytes": db_bytes(),
                           "schema_version": SCHEMA_VERSION}
    try:
        cx = _conn(conn)
        for name, sql in (
            ("files", "SELECT COUNT(*) FROM files WHERE indexed_ts IS NOT NULL"),
            ("files_tracked", "SELECT COUNT(*) FROM files"),
            ("chunks", "SELECT COUNT(*) FROM chunk_meta"),
            ("symbols", "SELECT COUNT(*) FROM symbols"),
            ("edges", "SELECT COUNT(*) FROM edges"),
            ("edges_resolved", "SELECT COUNT(*) FROM edges WHERE dst_file IS NOT NULL"),
            ("provides", "SELECT COUNT(*) FROM provides"),
            ("epochs", "SELECT COUNT(*) FROM epochs"),
            ("epochs_open", "SELECT COUNT(*) FROM epochs WHERE is_open=1"),
            ("ranges", "SELECT COUNT(*) FROM ranges"),
            ("events", "SELECT COUNT(*) FROM events"),
            ("indexed_bytes", "SELECT COALESCE(SUM(size),0) FROM files WHERE indexed_ts IS NOT NULL"),
            ("indexed_tokens", "SELECT COALESCE(SUM(tokens),0) FROM files WHERE indexed_ts IS NOT NULL"),
            ("read_tokens", "SELECT COALESCE(SUM(tokens),0) FROM events WHERE kind='read'"),
            ("dup_tokens", "SELECT COALESCE(SUM(dup_tokens),0) FROM events"),
            ("saved_tokens", "SELECT COALESCE(SUM(saved_tokens),0) FROM events"),
        ):
            try:
                out[name] = int(cx.execute(sql).fetchone()[0])
            except sqlite3.Error:
                out[name] = 0
        try:
            row = cx.execute("SELECT value FROM meta WHERE key='last_index'").fetchone()
            out["last_index"] = json.loads(row[0]) if row else None
        except Exception:
            out["last_index"] = None
        out["by_lang"] = {r["lang"]: int(r["n"]) for r in cx.execute(
            "SELECT lang, COUNT(*) AS n FROM files WHERE indexed_ts IS NOT NULL "
            "GROUP BY lang ORDER BY n DESC")}
    except Exception as exc:  # pragma: no cover
        out["error"] = type(exc).__name__
    return out


def vacuum(conn: Optional[sqlite3.Connection] = None) -> bool:
    """Compact the file: optimize, checkpoint, VACUUM, checkpoint. Order matters.

    FTS5 `optimize` merges every index segment into one by WRITING the merged
    segment and freeing the old pages -- so running it AFTER the VACUUM leaves
    all that space in the freelist and the file comes out BIGGER than it went in.
    And db_bytes() counts the -wal, which VACUUM has just written the entire
    database through, so a size taken before the final checkpoint reports a store
    that looks to have doubled at the moment it has just shrunk.

    optimize -> checkpoint -> VACUUM -> checkpoint. Every step is optional and a
    failure of any one of them is not a failure of the caller's delete.
    """
    try:
        cx = _conn(conn)
        try:
            cx.execute("INSERT INTO chunks(chunks) VALUES('optimize')")
        except sqlite3.Error:
            pass
        try:
            cx.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        except sqlite3.Error:
            pass
        cx.execute("VACUUM")
        try:
            cx.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        except sqlite3.Error:
            pass
        return True
    except Exception:
        return False


# --------------------------------------------------------------------------
# RETENTION.
#
# A recorded tool call costs a couple of hundred bytes of database and about as
# much ndjson, and a session costs a few MB of HTML in the reports tree. A daily
# heavy session reaches hundreds of MB a year, so there has to be something that
# can reach it: store.vacuum() and reset_residency() are useless without a
# command that calls them.
#
# The retention rule below is deliberately narrow. Residency is meaningless
# outside its epoch and an epoch is meaningless once its session is closed, so
# CLOSED epochs and their ranges are pure history. `events` is the evidence
# `oe savings` is built on, so it is kept far longer than residency and never
# trimmed below the window that command reads.
# --------------------------------------------------------------------------

PRUNE_DEFAULT_DAYS = 45


def prune(days: int = PRUNE_DEFAULT_DAYS, *, apply: bool = False,
          keep_sessions: Sequence[str] = (),
          conn: Optional[sqlite3.Connection] = None) -> Dict[str, Any]:
    """Count (apply=False) or delete (apply=True) everything older than `days`.

    Returns the same shape either way, so a dry run and a real run print
    identically and the caller cannot accidentally describe one as the other.
    Never touches an OPEN epoch or any session named in keep_sessions -- the
    live session's residency is what the guard is using right now.
    """
    out: Dict[str, Any] = {"days": int(days), "applied": bool(apply),
                           "events": 0, "ranges": 0, "epochs": 0,
                           "bytes_before": 0, "bytes_after": 0, "reclaimed": 0,
                           "error": ""}
    try:
        cutoff = time.time() - max(1, int(days)) * 86400.0
        cx = _conn(conn)
        out["bytes_before"] = db_bytes()
        keep = tuple(str(k) for k in keep_sessions if k)
        holes = ",".join("?" * len(keep))
        keep_clause = (" AND session_id NOT IN (%s)" % holes) if keep else ""

        dead_sql = ("SELECT epoch_id FROM epochs WHERE is_open=0 AND "
                    "COALESCE(ended_ts, started_ts) < ?" + keep_clause)
        dead = [int(r[0]) for r in cx.execute(dead_sql, (cutoff,) + keep).fetchall()]
        ev_sql = "SELECT count(*) FROM events WHERE ts < ?" + keep_clause
        out["events"] = int(cx.execute(ev_sql, (cutoff,) + keep).fetchone()[0] or 0)
        if dead:
            marks = ",".join("?" * len(dead))
            out["ranges"] = int(cx.execute(
                "SELECT count(*) FROM ranges WHERE epoch_id IN (%s)" % marks, dead).fetchone()[0] or 0)
        out["epochs"] = len(dead)
        if not apply:
            return out

        cx.execute("BEGIN IMMEDIATE")
        try:
            cx.execute("DELETE FROM events WHERE ts < ?" + keep_clause, (cutoff,) + keep)
            if dead:
                marks = ",".join("?" * len(dead))
                cx.execute("DELETE FROM ranges WHERE epoch_id IN (%s)" % marks, dead)
                cx.execute("DELETE FROM epochs WHERE epoch_id IN (%s)" % marks, dead)
            cx.execute("COMMIT")
        except Exception:
            cx.execute("ROLLBACK")
            raise
        # VACUUM cannot run inside a transaction and needs room for a copy of the
        # database; a failure here is not a failure of the prune.
        vacuum(cx)
        out["bytes_after"] = db_bytes()
        out["reclaimed"] = max(0, out["bytes_before"] - out["bytes_after"])
        return out
    except Exception as exc:
        out["error"] = repr(exc)[:200]
        return out


def quarantined(state: Optional[os.PathLike] = None) -> List[Dict[str, Any]]:
    """Databases a previous heal moved aside, newest first.

    _quarantine() renames rather than deletes, on purpose -- but a rename nobody
    ever looks at only accumulates: a machine that heals the same store
    repeatedly keeps every copy, unnoticed and unbounded. Listing them is what
    makes the rename honest.
    """
    rows: List[Dict[str, Any]] = []
    try:
        base = Path(state) if state is not None else db_path().parent
        for entry in base.glob("*.corrupt-*"):
            try:
                st = entry.stat()
            except OSError:
                continue
            rows.append({"path": str(entry), "bytes": int(st.st_size),
                         "mtime": float(st.st_mtime)})
    except Exception:
        return rows
    return sorted(rows, key=lambda r: -r["mtime"])


def reset_residency(session_id: str = "", *, agent_id: str = "",
                    conn: Optional[sqlite3.Connection] = None) -> int:
    """Drop recorded residency. With no session_id, drops everything closed --
    used by the installer and by `oe context reset`."""
    try:
        cx = _conn(conn)
        cx.execute("BEGIN IMMEDIATE")
        if session_id:
            cur = cx.execute("DELETE FROM ranges WHERE epoch_id IN "
                             "(SELECT epoch_id FROM epochs WHERE session_id=? AND agent_id=?)",
                             (session_id, agent_id))
            dropped = int(cur.rowcount or 0)
            cx.execute("UPDATE epochs SET is_open=0, ended_ts=? "
                       "WHERE session_id=? AND agent_id=? AND is_open=1",
                       (time.time(), session_id, agent_id))
        else:
            cur = cx.execute("DELETE FROM ranges WHERE epoch_id IN "
                             "(SELECT epoch_id FROM epochs WHERE is_open=0)")
            dropped = int(cur.rowcount or 0)
        cx.execute("COMMIT")
        return dropped
    except Exception:
        try:
            cx.execute("ROLLBACK")
        except Exception:
            pass
        return 0


# --------------------------------------------------------------------------
# Thin CLI (verification + `oe` plumbing). Nothing here runs on import.
# --------------------------------------------------------------------------

def _main(argv: List[str]) -> int:
    if not argv or argv[0] in ("-h", "--help"):
        print("usage: store.py {index ROOT... | search QUERY | subtree PATH [depth] "
              "| stats | vacuum}")
        return 0
    cmd, rest = argv[0], argv[1:]
    if cmd == "index":
        print(json.dumps(index_paths(rest or ["."]), indent=2))
    elif cmd == "search":
        for hit in search(" ".join(rest), k=10):
            print(json.dumps(hit))
    elif cmd == "subtree":
        depth = int(rest[1]) if len(rest) > 1 else 2
        print(json.dumps(subtree(rest[0], depth=depth), indent=2))
    elif cmd == "stats":
        print(json.dumps(stats(), indent=2))
    elif cmd == "vacuum":
        print(json.dumps({"ok": vacuum()}))
    else:
        print("unknown command: %s" % cmd)
        return 2
    return 0


if __name__ == "__main__":  # pragma: no cover
    import sys
    raise SystemExit(_main(sys.argv[1:]))
