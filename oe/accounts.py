"""Which Claude Code account paid for a session, and how well we know it.

The rule is deliberately trivial:

    email == the first account this machine saw  ->  'primary'
    any other login                          ->  'secondary' (then secondary-2, ...)
    no email recoverable                     ->  'unknown'

A label names a LOGIN this machine has seen, nothing else. There is no
personal/work split: which account is which is the user's business, and
`oe account rename` is how they say it.

Everything else in this module exists because the *email* is rarely on disk.
Claude Code keeps exactly one account in ~/.claude.json and overwrites it on
every switch, so the identity of a session that ran under a previous login has
to be recovered from weaker records. Each recovery path is named, and every
answer carries the name of the path that produced it, because "primary"
bracketed by a config snapshot and "primary" read out of the transcript are not
the same claim and must not render identically.

    assigned  the user said so (`oe account assign`)
    recorded  the transcript's own 'bridge-session' line names ownerAccountUuid
    stamped   we read ~/.claude.json while the session was live and wrote the
              answer down; this is how every FUTURE session gets labelled, and
              it survives the account switch that erases ~/.claude.json
    backup    a ~/.claude/backups/.claude.json.backup.<ms> snapshot brackets the
              session's start time and the snapshots either side of it agree
    unknown   nothing is known -- say so, never guess

PII: the email address and the accountUuid are identity, and they never leave
this module's state file under paths.state_dir(). Every field this module puts
on a row, a report payload or a meta.json is a LABEL plus a SOURCE plus (for
'backup') a sentence of evidence. That is safe by construction: there is no
code path that copies an address or a uuid into an artifact.
"""

from __future__ import annotations

import contextlib
import json
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

try:
    from . import paths, redact
except ImportError:  # executed as a plain script
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from oe import paths, redact  # type: ignore

# Labels are SELF-CONFIGURING. Nothing in this file names a person, an address
# or an employer: the first account the tool ever sees becomes "primary", the
# next "secondary" (then secondary-2, ...), and the address->label map lives in
# state/accounts.json -- local, never in the shared tree -- where `oe account
# rename` can change any of them. That is what lets the same checkout serve one
# account or three, on a personal machine or a work one.
LABEL_PRIMARY = "primary"
LABEL_SECONDARY = "secondary"
LABEL_UNKNOWN = "unknown"

# The names an install made before labels became self-configuring wrote into
# state. They are no longer labels: the one-time state upgrade (_upgrade) moves
# every stored one onto the current names, collision-safe, so a machine that
# used them keeps the same accounts under the names everybody else sees.
_LEGACY_LABELS: Tuple[str, ...] = ("personal", "work")

RESERVED_LABELS: Tuple[str, ...] = (LABEL_PRIMARY, LABEL_SECONDARY, LABEL_UNKNOWN)


def known_labels() -> Tuple[str, ...]:
    """Every label that exists on THIS machine: the reserved names plus any the
    user renamed to or that allocation produced. Used for `--account` choices
    and for iteration order in the rollups, so it must never be empty and must
    be stable on a machine with no history at all.
    """
    out: List[str] = [name for name in RESERVED_LABELS if name != LABEL_UNKNOWN]

    def offer(value: Any) -> None:
        text = str(value or "").strip()
        if text and text != LABEL_UNKNOWN and text not in out:
            out.append(text)

    try:
        state = load_state()
        for value in (state.get("label_map") or {}).values():
            offer(value)
        for bucket in ("assigned", "stamped"):
            rows = state.get(bucket)
            if isinstance(rows, dict):
                for row in rows.values():
                    if isinstance(row, dict):
                        offer(row.get("label"))
    except Exception:
        pass
    out.append(LABEL_UNKNOWN)
    return tuple(out)


# Back-compat for `accounts.LABELS`. PEP 562 module __getattr__ so the name
# keeps working for any caller while the VALUE is computed per machine.
def __getattr__(name: str):
    if name == "LABELS":
        return known_labels()
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

# Highest confidence first. resolve() walks this in order and stops at the
# first source that can answer, which IS the precedence rule.
SOURCE_ORDER: Tuple[str, ...] = (
    "assigned", "recorded", "stamped", "backup", "unknown")
SOURCE_RANK: Dict[str, int] = {name: i for i, name in enumerate(SOURCE_ORDER)}

# Which of those sources are a RECORD and which are a GUESS. A renderer must be
# able to tell them apart without knowing what each name means, because a
# document that prints a hint in the same ink as a record asserts something
# nobody checked -- and the artifacts are the half of this system that gets
# shared. 'backup' is circumstantial (a snapshot window, not the session); the
# others either read the answer or were told it. A heuristic source used to sit
# here too, guessing 'work' from an organization-level quota policy. It could
# only ever produce a label no login on the machine had, so it was removed
# rather than renamed.
LOW_CONFIDENCE_SOURCES: Tuple[str, ...] = ("backup",)

# What each source actually did, as a fixed sentence per enum value. Enumerated
# and constant, NOT generated text: this is what goes into report.html and the
# dashboard, so it may never carry an address, an organisation name, a path or
# a date. accounts.resolve() still returns the per-session `evidence` string for
# terminal output, which is local and ephemeral; this is the shareable form.
SOURCE_NOTE: Dict[str, str] = {
    "assigned": "Set by hand with `oe account assign`.",
    "recorded": "Read from the session transcript's own bridge-session record.",
    "stamped": "Captured from the logged-in account while the session was running.",
    "backup": ("No account is named for this session, but a local Claude Code config "
               "snapshot taken before it started and the next one taken after it both "
               "name the same account. That brackets the session; it does not record "
               "it. Confirm it with `oe account assign`."),
    "unknown": ("Nothing on disk names an account for this session -- usually because "
                "it ran before this tool was installed. Set it with `oe account assign`."),
}


def is_guess(source: Any) -> bool:
    """True when a label came from a heuristic rather than from a record."""
    return str(source or "unknown") in LOW_CONFIDENCE_SOURCES

CLAUDE_JSON = paths.CLAUDE_HOME.parent / ".claude.json"
BACKUPS_DIR = paths.CLAUDE_HOME / "backups"

# 2: 'personal'/'work' retired, the org-hint bucket dropped, and label_map
# entries for addresses that never logged in pruned. See _upgrade().
STATE_VERSION = 2
_STATE_NAME = "accounts.json"

# A 'bridge-session' line is NOT a header. Most transcripts that carry one put
# it in the first few hundred bytes, which is why a head-only scan looks
# sufficient -- but the line is emitted when the session is bridged, whenever
# that happens, so it can also sit megabytes into a long transcript. A head scan
# MISSES those and reports 'unknown' for a session whose owner is written down.
#
# So the scan is whole-file, and incremental: the byte offset reached is
# remembered per session, a later pass resumes from it, and a session whose uuid
# is already known is never opened again. Only the cold pass reads anything.
#
# One pass will read at most this many previously-unseen bytes across ALL
# sessions, mirroring the byte budget scan_sessions() already applies to costing
# so a cold cache cannot stall the first `oe watch` frame. `oe account list`
# passes an unlimited budget, because its whole job is the complete answer.
_SCAN_BYTES_PER_PASS = 48 * 1024 * 1024


def _now() -> float:
    return time.time()


# ---------------------------------------------------------------------------
# the rule
# ---------------------------------------------------------------------------


def _config_labels(config: Optional[Dict[str, Any]] = None) -> Dict[str, str]:
    """Address -> label pins from config.json (`accounts.labels`). Optional; a
    user who wants a specific name for a specific address writes it here and it
    outranks anything learned."""
    try:
        cfg = config if isinstance(config, dict) else paths.load_config()
        raw = (cfg.get("accounts") or {}).get("labels") or {}
        if not isinstance(raw, dict):
            return {}
        return {str(k).strip().lower(): str(v).strip()
                for k, v in raw.items() if str(v).strip()}
    except Exception:
        return {}


def _legacy_personal_email(config: Optional[Dict[str, Any]] = None) -> str:
    """The pre-self-configuring `accounts.personal_email` key, if a config still
    carries it. Honoured so an existing install keeps its personal/work split
    rather than being silently re-labelled by the new allocator on upgrade."""
    try:
        cfg = config if isinstance(config, dict) else paths.load_config()
        return str((cfg.get("accounts") or {}).get("personal_email") or "").strip().lower()
    except Exception:
        return ""


def _pinned_labels(config: Optional[Dict[str, Any]] = None) -> set:
    """Labels a config reserves for a specific address, whether or not the
    address has been seen yet."""
    out = set(_config_labels(config).values())
    if _legacy_personal_email(config):
        out.add(LABEL_PRIMARY)
    return out


def _login_addresses(state: Dict[str, Any],
                     config: Optional[Dict[str, Any]] = None) -> set:
    """Every address this machine has seen LOG IN, plus the pinned ones.

    identities is complete for logins: current_identity() and
    backup_attestations() both record every account they read. So an address
    outside this set was only ever MENTIONED somewhere -- in a transcript, in a
    commit trailer -- and is somebody else's.
    """
    out = {str((row or {}).get("email") or "").strip().lower()
           for row in (state.get("identities") or {}).values() if isinstance(row, dict)}
    out |= set(_config_labels(config))
    legacy = _legacy_personal_email(config)
    if legacy:
        out.add(legacy)
    out.discard("")
    return out


def _stored_label(text: str, config: Optional[Dict[str, Any]] = None) -> Optional[str]:
    """The label already decided for an address -- pin, legacy pin, learned map.
    Never allocates."""
    pinned = _config_labels(config).get(text)
    if pinned:
        return pinned
    legacy = _legacy_personal_email(config)
    if legacy and text == legacy:
        return LABEL_PRIMARY
    try:
        known = (load_state().get("label_map") or {}).get(text)
    except Exception:
        known = None
    if isinstance(known, str) and known.strip():
        return known.strip()
    return None


def known_label_for_email(email: Optional[str],
                          config: Optional[Dict[str, Any]] = None) -> Optional[str]:
    """The label of one of THIS machine's logins, or None. Never allocates.

    For the scrubber, which meets addresses in free text. An address qualifies
    only if this machine saw it log in; anything else is a third party, and
    labelling it would both claim it is one of your accounts and write it to
    state. label_for_email() is for addresses KNOWN to be logins.
    """
    text = str(email or "").strip().lower()
    if not text:
        return None
    try:
        if text not in _login_addresses(load_state(), config):
            return None
    except Exception:
        return None
    return _stored_label(text, config)


def _seed_label_map(state: Dict[str, Any]) -> bool:
    """Carry labels an older version already decided into the address map.

    Without this, upgrading re-runs allocation from empty and the account that
    has been 'work' for months becomes 'primary'. Every stored identity already
    holds the address and the label it was given, so the map is recoverable
    exactly. Returns True when it changed something.
    """
    mapping = state.setdefault("label_map", {})
    if mapping:
        return False
    changed = False
    for row in (state.get("identities") or {}).values():
        if not isinstance(row, dict):
            continue
        address = str(row.get("email") or "").strip().lower()
        label = str(row.get("label") or "").strip()
        if address and label and label != LABEL_UNKNOWN and address not in mapping:
            mapping[address] = label
            changed = True
    return changed


def allocate_label(address: str) -> str:
    """The label for an address never seen before: 'primary' for the first
    account on this machine, 'secondary' (then secondary-2, ...) for the rest.

    First-come, in the order the machine actually met them -- which is the only
    ordering available and the only one that does not require the tool to know
    anything about who the user is.
    """
    address = str(address or "").strip().lower()
    if not address:
        return LABEL_UNKNOWN
    chosen: List[str] = []

    def apply(state: Dict[str, Any]) -> bool:
        changed = _seed_label_map(state)
        mapping = state.setdefault("label_map", {})
        existing = str(mapping.get(address) or "").strip()
        if existing:
            chosen.append(existing)
            return changed
        # Pinned labels are taken too: a config that says "this address is
        # primary" must not see a second address allocated 'primary' merely
        # because the learned map happened to be empty.
        taken = {str(v).strip() for v in mapping.values()} | _pinned_labels()
        if not mapping and LABEL_PRIMARY not in taken:
            name = LABEL_PRIMARY
        else:
            name = LABEL_SECONDARY
            counter = 2
            while name in taken:
                name = f"{LABEL_SECONDARY}-{counter}"
                counter += 1
        mapping[address] = name
        chosen.append(name)
        return True

    _mutate(apply)
    return chosen[0] if chosen else LABEL_UNKNOWN


def rename_label(old: str, new: str) -> Dict[str, Any]:
    """Rename a label everywhere it is stored. Returns a summary dict."""
    old = str(old or "").strip()
    new = str(new or "").strip()
    result: Dict[str, Any] = {"old": old, "new": new, "addresses": 0,
                              "sessions": 0, "identities": 0, "ok": False}
    if not old or not new or old == new or new == LABEL_UNKNOWN:
        result["error"] = "need two different, non-empty labels ('unknown' is reserved)"
        return result

    def apply(state: Dict[str, Any]) -> bool:
        _seed_label_map(state)
        changed = False
        mapping = state.setdefault("label_map", {})
        for address, label in list(mapping.items()):
            if str(label).strip() == old:
                mapping[address] = new
                result["addresses"] += 1
                changed = True
        for bucket in ("assigned", "stamped"):
            rows = state.get(bucket)
            if not isinstance(rows, dict):
                continue
            for key, row in rows.items():
                if isinstance(row, dict) and str(row.get("label") or "").strip() == old:
                    row["label"] = new
                    result["sessions"] += 1
                    changed = True
        for row in (state.get("identities") or {}).values():
            if isinstance(row, dict) and str(row.get("label") or "").strip() == old:
                row["label"] = new
                result["identities"] += 1
                changed = True
        return changed

    _mutate(apply)
    result["ok"] = bool(result["addresses"] or result["sessions"] or result["identities"])
    return result


def label_for_email(email: Optional[str],
                    config: Optional[Dict[str, Any]] = None) -> str:
    """The label for an address, learning one the first time it is seen.

    Precedence, highest first:
      1. an explicit pin in config.json `accounts.labels`
      2. the legacy `accounts.personal_email` key, if a config still has it
      3. the learned address->label map in state/accounts.json
      4. allocation: first account seen is 'primary', the rest 'secondary*'
    """
    text = str(email or "").strip().lower()
    if not text:
        return LABEL_UNKNOWN
    return _stored_label(text, config) or allocate_label(text)


# ---------------------------------------------------------------------------
# local state -- the ONLY place an email or an accountUuid is ever written
# ---------------------------------------------------------------------------


def state_path() -> Path:
    return paths.state_dir() / _STATE_NAME


def _blank_state() -> Dict[str, Any]:
    return {
        "version": STATE_VERSION,
        # accountUuid -> {email, label, first_seen, last_seen}
        "identities": {},
        # session_id -> {"uuid": str|None, "label": str, "ts": float}
        "stamped": {},
        # session_id -> {"label": str, "ts": float}
        "assigned": {},
        # session_id -> {"uuid": str|None, "scanned_bytes": int}
        "recorded": {},
    }


_CACHE: Dict[str, Any] = {"mtime": -1.0, "data": None}
_ATTEST_CACHE: Dict[str, Any] = {"key": None, "value": None}


def _each_label_holder(state: Dict[str, Any]):
    """Every dict in state that carries a 'label', plus the address map itself."""
    for bucket in ("identities", "stamped", "assigned"):
        rows = state.get(bucket)
        if isinstance(rows, dict):
            for row in rows.values():
                if isinstance(row, dict) and "label" in row:
                    yield row


def _upgrade(state: Dict[str, Any]) -> bool:
    """Bring a state file written by an older build up to STATE_VERSION, in place.

    v1 -> v2, once:
      * label_map entries for addresses that never logged in here are dropped.
        Only the scrubber ever put them there -- it allocated a label for every
        address it met -- no session can resolve to one, and each is a third
        party's address sitting in local state.
      * 'personal'/'work' move to current names. Collision-safe: an install that
        allocated after the rename can hold 'work' AND 'secondary', and a blind
        rename would merge two accounts into one label.
      * the 'inferred' bucket goes with the heuristic that filled it.

    Runs only on a v1 file, so a label a user LATER chooses to call 'work' is
    theirs to keep. Never raises.
    """
    try:
        if int(state.get("version") or 1) >= 2:
            return False
        changed = state.pop("inferred", None) is not None
        mapping = state.get("label_map")
        if not isinstance(mapping, dict):
            mapping = {}
        logins = _login_addresses(state)
        for address in list(mapping):
            if str(address).strip().lower() not in logins:
                del mapping[address]
                changed = True
        labels = [str(v).strip() for v in mapping.values()]
        labels += [str(row.get("label") or "").strip() for row in _each_label_holder(state)]
        in_use = {name for name in labels if name and name not in _LEGACY_LABELS}
        rename: Dict[str, str] = {}
        for old in _LEGACY_LABELS:
            if old not in labels:
                continue
            wanted = ([LABEL_PRIMARY] if old == "personal" else []) + [LABEL_SECONDARY]
            name = next((n for n in wanted if n not in in_use), None)
            counter = 2
            while name is None:
                candidate = f"{LABEL_SECONDARY}-{counter}"
                counter += 1
                if candidate not in in_use:
                    name = candidate
            rename[old] = name
            in_use.add(name)
        if rename:
            for address, label in list(mapping.items()):
                if str(label).strip() in rename:
                    mapping[address] = rename[str(label).strip()]
            for row in _each_label_holder(state):
                if str(row.get("label") or "").strip() in rename:
                    row["label"] = rename[str(row["label"]).strip()]
            changed = True
        return changed
    except Exception:
        return False


def load_state() -> Dict[str, Any]:
    """The state file, memoised on its mtime. Never raises: a corrupt state file
    must cost labels, not the whole listing."""
    path = state_path()
    try:
        mtime = path.stat().st_mtime
    except OSError:
        mtime = 0.0
    cached = _CACHE.get("data")
    if cached is not None and _CACHE.get("mtime") == mtime:
        return cached
    data = _blank_state()
    if mtime:
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                for key, value in raw.items():
                    if key in data and isinstance(data[key], dict):
                        if isinstance(value, dict):
                            data[key] = value
                    else:
                        data[key] = value
                if "version" not in raw:
                    data["version"] = 1
        except Exception:
            data = _blank_state()
    # In memory only: READING state never writes it. A leak gate or a status
    # line that merely looks at labels must not rewrite the file under its user,
    # and a lint run once did exactly that. The next genuine write goes through
    # _mutate, which runs the same upgrade under the lock and persists it then.
    _upgrade(data)
    _CACHE["mtime"] = mtime
    _CACHE["data"] = data
    return data


@contextlib.contextmanager
def _state_lock():
    """Exclusive, blocking flock over the state file, or a no-op fallback.

    Blocking rather than non-blocking: every holder does one small read, one
    dict update and one atomic_write, so waiting is microseconds and dropping
    the write instead would be the very bug this closes. Failure to lock is
    never fatal -- an unlockable filesystem leaves the previous (racy) behaviour
    rather than losing the label entirely.
    """
    handle = None
    try:
        lock_path = state_path().with_suffix(".lock")
        handle = open(lock_path, "a+")
        import fcntl
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
    except Exception:
        if handle is not None:
            try:
                handle.close()
            except Exception:
                pass
            handle = None
    try:
        yield
    finally:
        if handle is not None:
            try:
                import fcntl
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
            except Exception:
                pass
            try:
                handle.close()
            except Exception:
                pass


def _mutate(apply) -> Dict[str, Any]:
    """Read-modify-write the state file, serialised by an exclusive file lock.

    Re-reading from disk is not enough on its own. The writers are genuinely
    concurrent -- the supervisor stamps live sessions every tick, each live
    session's watcher resolves its own row, and the CLI can assign at the same
    moment -- and read-modify-write without exclusion loses updates. A dropped
    `recorded` row only costs a re-scan, but a dropped `stamped` row is
    unrecoverable (a session can only be stamped while it is live) and a dropped
    `assigned` row silently discards something the user typed and was told had
    been written.

    So the whole read-modify-write runs while holding an exclusive flock on a
    sibling lock file. The lock is advisory and best-effort: where flock is
    unavailable this degrades to exactly the previous behaviour rather than
    failing, because nothing in this module may raise.

    `apply(state)` must return True when it changed something.
    """
    path = state_path()
    with _state_lock():
        data = _blank_state()
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                for key, value in raw.items():
                    if key in data and isinstance(data[key], dict):
                        if isinstance(value, dict):
                            data[key] = value
                    else:
                        data[key] = value
                if "version" not in raw:
                    data["version"] = 1
        except Exception:
            pass
        upgraded = _upgrade(data)
        try:
            changed = bool(apply(data))
        except Exception:
            changed = False
        changed = changed or upgraded
        if changed:
            data["version"] = STATE_VERSION
            try:
                paths.atomic_write(path, json.dumps(data, indent=2, sort_keys=True) + "\n")
                _CACHE["mtime"] = -1.0  # force the next load_state() off disk
                _CACHE["data"] = None
            except Exception:
                pass
    return data


# ---------------------------------------------------------------------------
# the live account
# ---------------------------------------------------------------------------


_OAUTH_CACHE: Dict[str, Tuple[float, int, Optional[Dict[str, Any]]]] = {}


def _read_oauth_account(path: Path) -> Optional[Dict[str, Any]]:
    """oauthAccount out of a .claude.json (live or backup). None if unreadable.

    A .claude.json runs to tens of KB, so a full json.loads is fine; the file has
    no stable line structure to scan cheaply anyway. Memoised on (mtime, size)
    because `oe watch` re-scans every two seconds and would otherwise re-parse
    six such files per tick for an answer that changes on a login, not a frame.
    """
    key = str(path)
    try:
        stat = path.stat()
        signature = (stat.st_mtime, stat.st_size)
    except OSError:
        _OAUTH_CACHE.pop(key, None)
        return None
    cached = _OAUTH_CACHE.get(key)
    if cached is not None and (cached[0], cached[1]) == signature:
        return cached[2]
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        _OAUTH_CACHE[key] = (signature[0], signature[1], None)
        return None
    account = raw.get("oauthAccount") if isinstance(raw, dict) else None
    result: Optional[Dict[str, Any]] = None
    if isinstance(account, dict):
        uuid = str(account.get("accountUuid") or "").strip()
        email = str(account.get("emailAddress") or "").strip()
        if uuid or email:
            result = {"uuid": uuid or None, "email": email or None}
    _OAUTH_CACHE[key] = (signature[0], signature[1], result)
    return result


def current_identity() -> Optional[Dict[str, Any]]:
    """The account ~/.claude.json currently holds: {uuid, email, label}.

    CONTAINS PII. Callers that render must take only ['label']. Reading it also
    remembers the uuid->email mapping, which is what later lets a 'recorded'
    bridge-session uuid be turned into a label after the account has switched
    away and ~/.claude.json no longer names it.
    """
    account = _read_oauth_account(CLAUDE_JSON)
    if account is None:
        return None
    label = label_for_email(account.get("email"))
    remember_identity(account.get("uuid"), account.get("email"))
    return {"uuid": account.get("uuid"), "email": account.get("email"), "label": label}


def remember_identity(uuid: Optional[str], email: Optional[str]) -> None:
    """Record uuid -> email in local state so the mapping outlives the login."""
    if not uuid or not email:
        return
    label = label_for_email(email)
    now = _now()
    # Fast path off the memoised state: _mutate() re-reads the file from disk on
    # every call, and this runs once per backup snapshot per scan tick.
    known = (load_state().get("identities") or {}).get(uuid)
    if (isinstance(known, dict) and known.get("email") == email
            and now - float(known.get("last_seen") or 0.0) < 3600.0):
        return

    def apply(state: Dict[str, Any]) -> bool:
        identities = state.setdefault("identities", {})
        row = identities.get(uuid)
        if isinstance(row, dict) and row.get("email") == email:
            # Only the freshness stamp moves; rewriting the file on every scan
            # tick for that alone is not worth the IO.
            if now - float(row.get("last_seen") or 0.0) < 3600.0:
                return False
            row["last_seen"] = now
            return True
        identities[uuid] = {"email": email, "label": label,
                            "first_seen": now, "last_seen": now}
        return True

    _mutate(apply)


def label_for_uuid(uuid: Optional[str],
                   state: Optional[Dict[str, Any]] = None) -> Optional[str]:
    """The label of a known accountUuid, or None when we never saw its email.

    None, NOT 'work'. An unrecognised uuid is an account whose address we have
    never read; calling it 'work' because it is not the personal uuid would be a
    guess, and the contract for this module is that it never guesses. The moment
    the meter runs once under that account, current_identity() learns the
    mapping and every session it owns resolves retroactively.
    """
    if not uuid:
        return None
    st = state if state is not None else load_state()
    row = (st.get("identities") or {}).get(str(uuid))
    if not isinstance(row, dict):
        return None
    # Recompute from the stored ADDRESS rather than trusting the stored label.
    # The rule lives in config.json precisely so that switching machines or
    # people is an edit to config; a label cached under a PREVIOUS
    # accounts.personal_email would otherwise outlive the config that produced
    # it and quietly contradict it forever, because remember_identity() is
    # write-once per address.
    email = row.get("email")
    if str(email or "").strip():
        return label_for_email(email)
    label = row.get("label")
    return str(label) if label in known_labels() else None


def whoami() -> Dict[str, Any]:
    """The CURRENT account's label and where it came from. No email, no uuid."""
    account = _read_oauth_account(CLAUDE_JSON)
    if account is None:
        return {"label": LABEL_UNKNOWN, "source": "unknown",
                "detail": "no oauthAccount in " + str(CLAUDE_JSON)}
    remember_identity(account.get("uuid"), account.get("email"))
    return {"label": label_for_email(account.get("email")),
            "source": "live",
            "detail": "read from ~/.claude.json oauthAccount"}


# ---------------------------------------------------------------------------
# 'recorded': the transcript's own bridge-session line
# ---------------------------------------------------------------------------


def _scan_recorded(transcript: Path, start: int = 0,
                   budget: Optional[List[int]] = None) -> Tuple[Optional[str], int]:
    """(ownerAccountUuid, absolute offset scanned to), resuming from `start`.

    Only whole lines count towards the returned offset, so the next pass resumes
    on a line boundary and can never split a JSON record in half.

    `budget` is a shared, mutable [bytes_left] for the whole pass, drained as
    this call reads; the caller resumes from the returned offset next time.
    Without it a cold cache would make the first `oe watch` tick read the whole
    corpus before it could draw.
    """
    offset = max(0, int(start or 0))
    try:
        size = transcript.stat().st_size
    except OSError:
        return None, offset
    if offset >= size:
        return None, offset
    try:
        with open(transcript, "rb") as handle:
            handle.seek(offset)
            for line in handle:
                length = len(line)
                if not line.endswith(b"\n"):
                    break          # partial trailing line: a writer is mid-append
                offset += length
                if b"bridge-session" in line:
                    try:
                        obj = json.loads(line.decode("utf-8", "replace"))
                    except Exception:
                        obj = None
                    # The substring above only NARROWS; the decision is
                    # structural. A transcript that merely quotes the word in a
                    # prompt would otherwise be labelled off its own text.
                    # off its own instructions.
                    if isinstance(obj, dict) and obj.get("type") == "bridge-session":
                        uuid = str(obj.get("ownerAccountUuid") or "").strip()
                        if uuid:
                            return uuid, offset
                if budget is not None:
                    budget[0] -= length
                    if budget[0] <= 0:
                        break
    except Exception:
        return None, offset
    return None, offset


def recorded_owner(session_id: str, transcript: Optional[Path],
                   budget: Optional[List[int]] = None) -> Optional[str]:
    """Cached ownerAccountUuid for a session; each byte is read at most once."""
    st = load_state()
    row = (st.get("recorded") or {}).get(session_id)
    if isinstance(row, dict) and row.get("uuid"):
        return str(row["uuid"])
    if transcript is None:
        return None
    start = int((row or {}).get("scanned_bytes") or 0) if isinstance(row, dict) else 0
    try:
        if start and start >= Path(transcript).stat().st_size:
            return None            # nothing appended since the last look
    except OSError:
        return None
    if budget is not None and budget[0] <= 0:
        return None                # this pass is out of budget; the next resumes
    uuid, scanned = _scan_recorded(Path(transcript), start, budget)
    if scanned == start and uuid is None:
        return None

    def apply(state: Dict[str, Any]) -> bool:
        table = state.setdefault("recorded", {})
        entry = {"uuid": uuid, "scanned_bytes": scanned}
        if table.get(session_id) == entry:
            return False
        table[session_id] = entry
        return True

    _mutate(apply)
    return uuid


# ---------------------------------------------------------------------------
# 'stamped': capture the live account the first time we see a session
# ---------------------------------------------------------------------------


def stamp_session(session_id: str, *, write_meta: bool = True) -> Optional[Dict[str, Any]]:
    """Bind a session to the account that is logged in RIGHT NOW, once.

    Called only for sessions that are currently live: the logged-in account is
    evidence about a session that is running, and evidence about nothing at all
    about one that last wrote three weeks ago. Stamping an idle session with
    today's login would manufacture history, which is worse than 'unknown'.

    Write-once by contract -- a stamp is a record of what was true at capture
    time, and a later re-stamp under a different login would silently rewrite
    the past.
    """
    session_id = str(session_id or "")
    if not session_id:
        return None
    st = load_state()
    existing = (st.get("stamped") or {}).get(session_id)
    if isinstance(existing, dict) and existing.get("label") in known_labels():
        return existing
    identity = current_identity()
    if identity is None or not identity.get("email"):
        return None
    entry = {"uuid": identity.get("uuid"), "label": identity["label"], "ts": _now()}

    def apply(state: Dict[str, Any]) -> bool:
        table = state.setdefault("stamped", {})
        if isinstance(table.get(session_id), dict):
            return False               # someone else stamped it first; theirs wins
        table[session_id] = entry
        return True

    _mutate(apply)
    if write_meta:
        _write_meta_label(session_id, entry["label"], "stamped")
    return entry


def _write_meta_label(session_id: str, label: str, source: str) -> None:
    """Mirror the label into <reports>/sessions/<id>/meta.json.

    Label and source ONLY. meta.json lives in the reports tree, which is an
    artifact directory, so the uuid and the address stay behind in state_dir().
    Merges rather than replaces: the SessionStart/SessionEnd hooks own other
    keys in this same file.
    """
    try:
        meta_path = paths.session_report_dir(session_id) / "meta.json"
        meta: Dict[str, Any] = {}
        try:
            loaded = json.loads(meta_path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                meta = loaded
        except Exception:
            meta = {}
        if meta.get("account_source") == "stamped" and meta.get("account_label") in known_labels():
            return                      # write-once, as above
        if meta.get("account_label") == label and meta.get("account_source") == source:
            return
        meta["account_label"] = label
        meta["account_source"] = source
        # meta.json is an artifact. The two keys written here are enums, but the
        # file is a MERGE of what the hooks and the supervisor also put there,
        # so the whole text goes through the same gate as the report documents.
        text = json.dumps(meta, indent=2) + "\n"
        redact.guard(text, str(meta_path))
        paths.atomic_write(meta_path, text)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# 'backup': the ~/.claude/backups snapshots as a time -> account map
# ---------------------------------------------------------------------------


def backup_attestations(include_live: bool = True) -> List[Dict[str, Any]]:
    """Every (time, account) pair recoverable from disk, oldest first.

    A backup at mtime T is a copy of ~/.claude.json as it stood at T, so it
    attests which account was logged in AT T -- nothing about the gaps. The live
    file adds one attestation for 'now'. The snapshots typically reach back hours
    rather than days, which is why this is the fourth-choice source and not the
    first.
    """
    try:
        entries = sorted(BACKUPS_DIR.glob(".claude.json.backup.*"))
    except Exception:
        entries = []
    # Cache on the set of files and their mtimes: `oe watch` calls this every
    # tick and each miss parses six such documents.
    try:
        signature: Any = (include_live, tuple((e.name, e.stat().st_mtime) for e in entries),
                          CLAUDE_JSON.stat().st_mtime if include_live else 0)
    except OSError:
        signature = None
    if signature is not None and _ATTEST_CACHE.get("key") == signature:
        return list(_ATTEST_CACHE.get("value") or [])
    out: List[Dict[str, Any]] = []
    for entry in entries:
        try:
            mtime = entry.stat().st_mtime
        except OSError:
            continue
        account = _read_oauth_account(entry)
        if account is None:
            continue
        remember_identity(account.get("uuid"), account.get("email"))
        out.append({"at": mtime, "uuid": account.get("uuid"),
                    "label": label_for_email(account.get("email")),
                    "path": entry.name})
    if include_live:
        account = _read_oauth_account(CLAUDE_JSON)
        if account is not None:
            try:
                mtime = CLAUDE_JSON.stat().st_mtime
            except OSError:
                mtime = _now()
            out.append({"at": mtime, "uuid": account.get("uuid"),
                        "label": label_for_email(account.get("email")),
                        "path": ".claude.json"})
    out.sort(key=lambda item: item["at"])
    if signature is not None:
        _ATTEST_CACHE["key"] = signature
        _ATTEST_CACHE["value"] = list(out)
    return out


def backup_label(started_at: Optional[float],
                 attestations: Optional[List[Dict[str, Any]]] = None
                 ) -> Optional[Dict[str, Any]]:
    """The account a snapshot window brackets, or None when it cannot say.

    Requires the attestations either side of the session start to AGREE. If they
    disagree the switch happened somewhere inside that gap and the window cannot
    place the session on one side of it -- that is exactly the case where a
    guess would be wrong, so it returns None instead.
    """
    if not started_at:
        return None
    marks = attestations if attestations is not None else backup_attestations()
    if not marks:
        return None
    before = None
    after = None
    for mark in marks:
        if mark["at"] <= started_at:
            before = mark
        elif after is None:
            after = mark
    if before is None:
        # The session predates every snapshot on disk. The backups only reach
        # back a few hours; older than that, they know nothing.
        return None
    if after is not None and after.get("uuid") != before.get("uuid"):
        return None
    if before.get("label") not in known_labels() or before.get("label") == LABEL_UNKNOWN:
        return None
    span = "%s .. %s" % (_short_time(before["at"]),
                         _short_time(after["at"]) if after else "now")
    return {"label": before["label"], "evidence": "backup snapshot window " + span}


def _short_time(epoch: float) -> str:
    try:
        return time.strftime("%Y-%m-%d %H:%M", time.localtime(epoch))
    except Exception:
        return "?"


# ---------------------------------------------------------------------------
# resolution
# ---------------------------------------------------------------------------


def _epoch(value: Any) -> Optional[float]:
    """Accept an epoch float or an ISO-8601 string; None when neither parses."""
    if value in (None, ""):
        return None
    if isinstance(value, (int, float)):
        return float(value) or None
    text = str(value).strip().replace("Z", "+00:00")
    try:
        from datetime import datetime
        return datetime.fromisoformat(text).timestamp()
    except Exception:
        return None


def resolve(session_id: str, transcript: Optional[Path] = None, *,
            started_at: Any = None, active: bool = False,
            attestations: Optional[List[Dict[str, Any]]] = None,
            budget: Optional[List[int]] = None) -> Dict[str, Any]:
    """{label, source, evidence} for one session, best source first.

    `active` permits a live stamp (see stamp_session); `budget` is the shared [bytes_left] for the transcript scan.
    """
    session_id = str(session_id or "")
    # Capture BEFORE resolving, not as a fallback. A stamp is a record of what
    # was true while the session ran, and it is worth taking even when a
    # bridge-session line already answers -- that line can be absent from the
    # next session, and ~/.claude.json is erased by the next account switch.
    # Taking it here is also what teaches the identity store the uuid -> email
    # mapping that later makes 'recorded' resolvable for a switched-to account.
    if active:
        stamp_session(session_id)
    state = load_state()

    assigned = (state.get("assigned") or {}).get(session_id)
    if isinstance(assigned, dict) and assigned.get("label") in known_labels():
        return {"label": str(assigned["label"]), "source": "assigned", "evidence": ""}

    uuid = recorded_owner(session_id, transcript, budget)
    label = label_for_uuid(uuid, state)
    if label and label != LABEL_UNKNOWN:
        return {"label": label, "source": "recorded", "evidence": ""}

    stamped = (state.get("stamped") or {}).get(session_id)
    if isinstance(stamped, dict) and stamped.get("label") in known_labels():
        return {"label": str(stamped["label"]), "source": "stamped", "evidence": ""}

    from_backup = backup_label(_epoch(started_at), attestations)
    if from_backup:
        return {"label": from_backup["label"], "source": "backup",
                "evidence": from_backup["evidence"]}


    return {"label": LABEL_UNKNOWN, "source": "unknown", "evidence": ""}


def annotate_row(row: Dict[str, Any], *,
                 attestations: Optional[List[Dict[str, Any]]] = None,
                 budget: Optional[List[int]] = None) -> Dict[str, Any]:
    """Add account_label / account_source / account_evidence to a scan row.

    Never raises and never removes anything: a row that cannot be resolved comes
    back labelled 'unknown', which is a real answer.
    """
    try:
        transcript = row.get("transcript_path")
        answer = resolve(
            str(row.get("session_id") or ""),
            Path(transcript) if transcript else None,
            started_at=row.get("started_at") or row.get("mtime"),
            active=bool(row.get("is_active")),
            attestations=attestations,
            budget=budget)
    except Exception:
        answer = {"label": LABEL_UNKNOWN, "source": "unknown", "evidence": ""}
    row["account_label"] = answer["label"]
    row["account_source"] = answer["source"]
    if answer.get("evidence"):
        row["account_evidence"] = answer["evidence"]
    else:
        row.pop("account_evidence", None)
    return row


def annotate_rows(rows: List[Dict[str, Any]], *,
                  scan_bytes: Optional[int] = _SCAN_BYTES_PER_PASS
                  ) -> List[Dict[str, Any]]:
    """annotate_row over a listing, reading the backup snapshots once.

    `scan_bytes` is the whole pass's transcript-reading allowance; None lifts it.
    A pass that runs out leaves the remaining sessions 'unknown' for this frame
    and resumes from the byte it stopped at on the next one -- the same
    "another cheap pass finishes it" contract the cost cache already has.
    """
    try:
        attestations = backup_attestations()
    except Exception:
        attestations = []
    budget: Optional[List[int]] = None if scan_bytes is None else [int(scan_bytes)]
    for row in rows or []:
        try:
            annotate_row(row, attestations=attestations, budget=budget)
        except Exception:
            row.setdefault("account_label", LABEL_UNKNOWN)
            row.setdefault("account_source", "unknown")
    return rows


# ---------------------------------------------------------------------------
# filtering, rollups, assignment
# ---------------------------------------------------------------------------


def normalise_label(value: Any) -> Optional[str]:
    """A user-typed label -> a canonical one, else None.

    Matches any label this machine actually knows (see known_labels()), plus a
    unique one-letter prefix of it. Never a fixed vocabulary: the labels are
    allocated per machine and renameable, so hardcoding any fixed names here
    would reject the name the user chose."""
    text = str(value or "").strip().lower()
    if not text:
        return None
    for label in known_labels():
        if label == text or (len(text) == 1 and label.startswith(text)):
            return label
    return None


def filter_rows(rows: Iterable[Dict[str, Any]], wanted: Any) -> List[Dict[str, Any]]:
    """Rows whose label matches.

    An EMPTY filter is 'no filter' and passes everything through. A non-empty
    filter that names no label matches nothing: handing back the full list
    there would give a caller every session while it believed it had filtered,
    and a rollup that is silently unfiltered is exactly the miscount this
    module exists to prevent. bin/oe validates the argument and reports it
    before calling; this is the library-side floor under that.
    """
    if wanted is None or not str(wanted).strip():
        return list(rows)
    label = normalise_label(wanted)
    if label is None:
        return []
    return [row for row in rows if (row.get("account_label") or LABEL_UNKNOWN) == label]


def rollup(rows: Iterable[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """Per-label spend / tokens / calls / sessions, plus a provenance histogram.

    Costs follow the same rule the rest of the package uses: a row that was not
    priced this pass (cost_known False) contributes to `unpriced`, not a silent
    zero to `cost_usd`.
    """
    out: Dict[str, Dict[str, Any]] = {}
    for label in known_labels():
        out[label] = {"label": label, "sessions": 0, "cost_usd": 0.0,
                      "total_tokens": 0, "calls": 0, "unpriced": 0,
                      "estimate": False, "sources": {}}
    for row in rows or []:
        label = row.get("account_label") or LABEL_UNKNOWN
        bucket = out.setdefault(label, {"label": label, "sessions": 0, "cost_usd": 0.0,
                                        "total_tokens": 0, "calls": 0, "unpriced": 0,
                                        "estimate": False, "sources": {}})
        bucket["sessions"] += 1
        source = row.get("account_source") or "unknown"
        bucket["sources"][source] = bucket["sources"].get(source, 0) + 1
        if row.get("cost_known", True):
            try:
                bucket["cost_usd"] += float(row.get("cost_usd") or 0.0)
            except (TypeError, ValueError):
                pass
        else:
            bucket["unpriced"] += 1
        if row.get("cost_is_estimate"):
            bucket["estimate"] = True
        try:
            bucket["total_tokens"] += int(row.get("total_tokens") or 0)
            bucket["calls"] += int(row.get("calls") or 0)
        except (TypeError, ValueError):
            pass
    return out


def provenance_counts(rows: Iterable[Dict[str, Any]]) -> Dict[str, int]:
    """How many sessions each source accounted for, in precedence order.

    Sums to len(rows). A source this module does not know about is reported
    under its own name after the known ones rather than dropped: the histogram
    sits next to a per-account rollup that DOES count every row, and two
    figures over the same rows that disagree by a silent omission is worse than
    an unfamiliar row label.
    """
    counts: Dict[str, int] = {name: 0 for name in SOURCE_ORDER}
    for row in rows or []:
        source = str(row.get("account_source") or "unknown")
        counts[source] = counts.get(source, 0) + 1
    out = {name: counts[name] for name in SOURCE_ORDER if counts.get(name)}
    for name in sorted(counts):
        if name not in out and counts[name]:
            out[name] = counts[name]
    return out


def assign(session_ids: Iterable[str], label: str, *, dry_run: bool = False
           ) -> List[Dict[str, Any]]:
    """Set 'assigned' provenance on each session. Idempotent.

    Returns one change record per session -- {session_id, before, after,
    before_source, changed} -- so the caller can print what it WILL do before
    doing it. A session already assigned to the same label reports changed=False
    and no write happens.
    """
    target = normalise_label(label)
    if target is None or target == LABEL_UNKNOWN:
        raise ValueError("assign a label of " + " / ".join(
            repr(name) for name in known_labels() if name != LABEL_UNKNOWN))
    ids = [str(sid) for sid in session_ids if str(sid or "").strip()]
    state = load_state()
    changes: List[Dict[str, Any]] = []
    for sid in ids:
        current = resolve(sid)
        already = (state.get("assigned") or {}).get(sid)
        same = isinstance(already, dict) and already.get("label") == target
        changes.append({
            "session_id": sid,
            "before": current["label"],
            "before_source": current["source"],
            "after": target,
            "changed": not same,
        })
    if dry_run or not any(item["changed"] for item in changes):
        return changes
    now = _now()

    def apply(st: Dict[str, Any]) -> bool:
        table = st.setdefault("assigned", {})
        touched = False
        for item in changes:
            if not item["changed"]:
                continue
            table[item["session_id"]] = {"label": target, "ts": now}
            touched = True
        return touched

    _mutate(apply)
    for item in changes:
        if item["changed"]:
            _clear_meta_label(item["session_id"], target)
    return changes


def unassign(session_ids: Iterable[str], *, dry_run: bool = False
             ) -> List[Dict[str, Any]]:
    """Drop the user's override so the session falls back to its evidence."""
    ids = [str(sid) for sid in session_ids if str(sid or "").strip()]
    state = load_state()
    assigned = state.get("assigned") or {}
    changes = [{"session_id": sid,
                "before": (assigned.get(sid) or {}).get("label"),
                "before_source": "assigned" if sid in assigned else
                                 resolve(sid)["source"],
                "after": None,
                "changed": sid in assigned}
               for sid in ids]
    if dry_run or not any(item["changed"] for item in changes):
        return changes

    def apply(st: Dict[str, Any]) -> bool:
        table = st.setdefault("assigned", {})
        touched = False
        for item in changes:
            if item["changed"] and table.pop(item["session_id"], None) is not None:
                touched = True
        return touched

    _mutate(apply)
    for item in changes:
        if item["changed"]:
            _clear_meta_label(item["session_id"], None)
    return changes


def _clear_meta_label(session_id: str, label: Optional[str]) -> None:
    """Keep meta.json honest after an assignment.

    An assignment outranks a stamp, so the mirrored label has to move with it --
    otherwise the reports tree keeps asserting a label the CLI no longer agrees
    with. Passing None removes the mirror and lets the evidence speak again.
    """
    try:
        meta_path = paths.session_report_dir(session_id) / "meta.json"
        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
        except Exception:
            return
        if not isinstance(meta, dict):
            return
        if label is None:
            if "account_label" not in meta and "account_source" not in meta:
                return
            meta.pop("account_label", None)
            meta.pop("account_source", None)
        else:
            if meta.get("account_label") == label and meta.get("account_source") == "assigned":
                return
            meta["account_label"] = label
            meta["account_source"] = "assigned"
        text = json.dumps(meta, indent=2) + "\n"     # artifact: same gate
        redact.guard(text, str(meta_path))
        paths.atomic_write(meta_path, text)
    except Exception:
        pass
