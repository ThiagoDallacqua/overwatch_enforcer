# Configuration

*Part of the [Overwatch Enforcer](../README.md) documentation. [← README](../README.md)*

## Nothing is hardcoded

Nothing about a person, an employer or a repository is in any shipped source file, and
nothing in the code depends on this directory being called anything in particular.

* **The install root** is derived from `__file__` (`OE_INSTALL_ROOT` overrides it, for a hook
  script copied out of the tree). No absolute literal — not in `install.py`, not in any hook,
  not in `bin/oe`. `overwatch_enforcer` (the repository), `overwatch-enforcer` (the
  conventional install directory) and any other name you give it are the same tree to all of
  them.
* **`~/.claude`** comes from `$HOME`, or `CLAUDE_CONFIG_DIR` when set — the same variable
  Claude Code itself honours.
* **The reports root** comes from `config.json`, a file the repository does not track, so a
  clone starts with no local value at all and the portable default applies. If a value *is*
  present and is not writable — which is what happens when `config.json` travels with a
  tarball and names somebody else's home — it falls back to `~/.claude/reports/usage` rather
  than writing nothing or throwing inside a status line. That is a misconfiguration people
  **inherit**, not one they made, and untracking the file is what stops a clone inheriting one.
* **Account labels self-configure.** There is no address in any shipped file. The first
  account the tool sees becomes `primary`, the next `secondary`, and the address-to-label map
  lives in `state/accounts.json`, which never leaves the machine. `oe account rename secondary
  work` renames it everywhere; `config.json` → `accounts` can pin one explicitly.
* **Provenance is labelled, never guessed silently.** `recorded` = the transcript's own
  bridge-session owner id. `inferred` = a low-confidence hint, printed with its evidence.
  `unknown` = nothing on disk names an account.

**On a machine with no history** every command runs and returns a sensible empty state rather
than a traceback. Captured against an empty `$HOME` with no transcripts, no state directory
and no `config.json`:

```
$ oe sessions            -> no sessions
$ oe status              -> no sessions found under ~/.claude/projects
$ oe rereads --all       -> no file reads found for that selector
$ oe savings --all       -> savings  0 transcripts / measured spend in scope  $0.00
$ oe shrink --all        -> no file reads found for that selector
$ oe brief "anything"     -> nothing retrieved for this prompt
$ oe audit --all         -> clean: 0 artifact(s), 0 findings
$ oe find --stats        -> "files": 0, "db_bytes": 0
$ oe account whoami      -> unknown   source: unknown
                            no oauthAccount in ~/.claude.json
$ oe whois session_07    -> unknown pseudonym 'session_07'; the map is ~/overwatch_enforcer/state/session-map.json
$ oe doctor --no-pricing -> primary path healthy, 1 warnings, 2 optional extras not installed
```

The one warning is `oe on PATH`: a clone that has not been through `install.py --yes` has no
`oe` symlink, which is a fact about the shell and not about the tool. Exit status is 0.

What that run created: the reports root (`~/.claude/reports/usage`, empty), the state
directory, an empty `state/context.db`, and CPython's own `__pycache__` beside the modules it
imported. Nothing outside the install root and the reports root.

## config.json

Lives at `$OE/config.json`, and **the whole file is optional**. It is not tracked by the
repository, so a fresh clone has none until `install.py --yes` copies `config.example.json`
into place — and a machine that never runs the installer never has one either. Missing keys,
and a missing file, fall back to `DEFAULT_CONFIG` in `oe/paths.py` by deep merge; a corrupt
file degrades to the defaults rather than breaking a status line. **Zero config is the
supported state, not a degraded one.**

One command writes this file, and it is yours to invoke: `install.py --yes` creates it if it
is absent. Nothing else touches it.

| key | default | meaning |
|---|---|---|
| `reports_root` | `~/.claude/reports/usage` | where artifacts are written; falls back to the default if not writable |
| `refresh_seconds` | `5` | watcher rebuild cadence |
| `idle_exit_seconds` | `1800` | a per-session watcher gives up after this much silence |
| `currency` | `"USD"` | display only |
| `budget.session_usd` | `25.0` | the per-session budget the insights and the budget line compare against |
| `budget.daily_usd` | `150.0` | the per-day budget |
| `budget.warn_pct` | `80` | warn threshold, as a percentage of budget |
| `scan.active_within_seconds` | `900` | a session counts as "recent" within this |
| `scan.tail_bytes` | `262144` | bytes read from the end in a cheap scan |
| `scan.head_bytes` | `65536` | bytes read from the start in a cheap scan |
| `scan.max_sessions` | `500` | cap on a scan |
| `insights.top_turns` | `8` | rows in the per-turn insight |
| `insights.top_tools` | `12` | rows in the tool table |
| `insights.top_subagents` | `8` | rows in the subagent insight |
| `insights.reread_threshold` | `3` | repeats before a target is called redundant work |
| `insights.large_result_bytes` | `40000` | a tool result at or above this is called out |
| `insights.carry_usd_per_1k` | `0.126` | the fixed forward-carry rate `oe rereads` prices its `calibrated` column with. Not in the shipped file; add it to override |
| `report.include_raw_calls` | `true` | write the raw-API-requests section of the report |
| `report.max_raw_calls` | `4000` | cap on that section |
| `accounts` | `{}` | optional explicit label pins; **empty by design** — labels self-configure |
| `redact_cli` | `"auto"` | `auto` \| `always` \| `never` ([Privacy](privacy.md#the-controls)) |

A `supervisor` block is honoured if you add one. None of these keys is in the shipped file;
each falls back to the value below:

| key | default | meaning |
|---|---|---|
| `poll_seconds` | `2.0` | tick cadence (floored at 0.25) |
| `discover_seconds` | `5.0` | full liveness sweep cadence (floored at 1.0) |
| `new_session_scan_seconds` | `1.0` | the cheap "did a transcript appear?" scan (floored at 0.2) |
| `idle_finalize_seconds` | `300.0` | finalize a quiet session (floored at 5.0; also honoured at the top level of `config.json`) |
| `activate_within_seconds` | `900.0` | adopt a session that moved this recently |
| `hard_idle_seconds` | `14400.0` | give up entirely |
| `max_sessions` | `8` | concurrent tracked sessions |
| `dashboard_interval_seconds` | `30.0` | dashboard rebuild cadence |
| `max_track_age_seconds` | `86400.0` | drop a track older than this |
| `report_interval_seconds` | per-session default | how often `report.html` is rebuilt while a session keeps writing |

## Environment variables

Ours:

| variable | default | effect |
|---|---|---|
| `OE_INSTALL_ROOT` | derived from `__file__` | override the install root, for a hook script copied out of the tree |
| `OE_STATE_DIR` | `$OE/state` | relocate all local state — the test-harness lever |
| `OE_REPORTS_ROOT` | `config.json` → `reports_root` | relocate the reports tree for this process and its children; deliberately does **not** move state |
| `OE_CONTEXT_DB` | `$OE_STATE_DIR/context.db` | relocate the context index |
| `OE_REDACT` | unset | `always`-family or `never`-family; anything else defers to `config.json` |
| `OE_NO_AUTOSTART` | unset | any non-empty value disables the shell-rc autostart line without editing it |
| `OE_COLOR` | unset | force colour on or off |
| `OE_SESSION_ID` | unset | name the session a command should resolve to, after `CLAUDE_SESSION_ID` |
| `OE_STATUSLINE_TIMING` | unset | emit status-line timing diagnostics |
| `OE_INJECTOR_SCREEN` | unset | control what the `UserPromptSubmit` budget line puts on screen |

Claude Code's, which this tool **reads and never sets**:

| variable | effect on us |
|---|---|
| `CLAUDE_CONFIG_DIR` | relocates `~/.claude`; honoured everywhere |
| `CLAUDE_SESSION_ID` | the session a command resolves to when none is named |

`OE_REPORTS_ROOT` has one behaviour worth knowing: a reports tree named through it is read as
somebody else's, so a legacy `.state/` inside it is never migrated away. That is what makes
`oe audit --all` on a tree a colleague handed you a real check rather than a self-fulfilling
one.
