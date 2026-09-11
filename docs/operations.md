# Limits, troubleshooting and layout

*Part of the Overwatch Enforcer documentation. [← README](../README.md)*

## Known limits

**Computed totals are floors.** Sidechain (subagent) transcripts never receive the final
`message_delta` usage record, so the last output-token count of every subagent request is
missing from disk. The scan takes the largest mid-stream snapshot per `requestId` — the
closest the file gets — and still lands under Claude Code's own figure, by more on
subagent-heavy sessions than on plain ones. This is unrecoverable data loss in the source,
not an arithmetic choice. Such figures are printed with a leading `~` and labelled
`[measured]`.

**`cost-state` includes requests that are in no transcript.** Its `modelUsage` always carries
a `claude-haiku-4-5` row for title and summary generation, whose requests are never written
anywhere. A `[billed]` total therefore includes work a `[measured]` total cannot see. That is
why the two are labelled apart and never silently mixed:

| label | meaning |
|---|---|
| `[billed]` | every request falls inside a `cost-state` checkpoint. Claude Code's own number. Exact. |
| `[billed+measured]` | billed for the checkpointed runs, our measured price for the requests no checkpoint covers. Printed with a leading `~`. |
| `[measured]` / `~$…` | no checkpoint exists yet. Our number, same formula Claude Code bills with. **A floor.** |
| `[queued]` | not costed on this pass; the next one picks it up. |

A running session usually has no checkpoint covering its most recent work, which is exactly
why the live figure is computed rather than billed.

**A model the pricing catalog does not know is counted as $0.00.** The report is written
anyway and the gap is named in it rather than the run aborting. `summary.md` grows a
`## Pricing gap` section and `report.html` a matching footer:

```
## Pricing gap

6 request(s) used a model this build's pricing catalog has no entry for (claude-zeta-9-20260101), and were counted as $0.00. Every dollar figure above is therefore a FLOOR. `oe reprice` refreshes the catalog.
```

**There is no per-tool wall time at all.** It is in the transcript nowhere, and `v1.0.2`
registers no hook on the tool-call path to collect it, so the tool table shows counts, result
bytes and error counts and says *no timing* on every session, installed or not.

**An `oe rereads` total is a ceiling, not a saving.** Most repeat reads are a *different
context window* opening the file for the first time, which nothing can recover. The `windows`
column is what separates the two; read it before you treat a row as money on the table.

**Account attribution is only certain where a record exists.** `recorded` and `stamped` are
records; `backup` is circumstantial and marked so; `unknown` is honest — and on a new install
it covers most of history, because a session can only be stamped while it is running.

**Compaction is approximate.** There is no snapshot of the context immediately before a
compaction; what the transcript records is used, and nothing more precise is claimed.

**Liveness is inferred, and on macOS it degrades.** Claude Code does not hold the transcript
open, so there is no file descriptor to look at. On Linux a session counts as running from
the newest write anywhere in its tree (agent files included — a long fan-out writes nothing to
the main transcript for minutes) combined with the running `claude` PIDs and their
`/proc/<pid>/cwd`. Without `/proc` the PID half is unavailable and liveness falls back to
mtime alone. See
[Verified on Linux](install.md#verified-on-linux-reasoned-but-untested-on-macos).

**`oe slice`, `oe find` and `oe deps --body` print file contents even when piped**, and
`oe rereads` prints file paths. Everything else, `--json` included, is allowlist-projected. A
basename that trips a redaction rule is rewritten in the header, which breaks the `find` →
`slice` round trip unless you use `--no-redact` or a terminal. See
[The retrieval exception](privacy.md#the-retrieval-exception).

**RTREE and JSON1 are checked but not used.** The dependency checklist probes them as headroom
checks; the shipped schema creates no rtree table and no `json_*` index.

**Plain `oe doctor` cannot tell you that a single hook event is missing.** Its hooks section
emits a row per event that IS wired, so two-of-three renders like three-of-three; only "none
of N wired" is called out. That matters after a `git pull` that adds an event. The checklist's
`hooks wired` row is the one that sees it — `oe doctor --install`, or `install.py --check` —
and re-running `install.py --yes` repairs it and names the events that were missing.

**All-time means "every transcript still on disk."** Deleting a project directory deletes its
history from this tool too.

**macOS is unverified.** No Mac was used at any point.

## Troubleshooting

### `oe doctor` first

```sh
$OE/bin/oe doctor
```

Exit 0 means the primary path is healthy. The optional extras (`statusLine`, hooks) are
reported as `○ not installed (optional)` and never fail the check. `--no-pricing` skips the
read of the Claude Code binary when you just want the fast answer.

For `oe: command not found`, which is the common one and is not a failed install, see
[If oe is not found](install.md#if-oe-is-not-found).

### After a Claude Code upgrade: `oe reprice`

`oe doctor` re-extracts the pricing catalog from the newest installed binary and **fails if
it disagrees** with `oe/pricing.py`, because a stale table makes every dollar on the screen
wrong.

```sh
$OE/bin/oe reprice
```

That rewrites the generated block in `oe/pricing.py` from the binary and leaves a
`oe/pricing.py.bak` beside it. The cost cache records the pricing version it was built with
and **discards itself when that changes**, so old dollars computed at old rates are never
mixed in — which means `oe doctor` may report `N still priming` for a few runs afterwards.
Run a couple of scans and it settles.

### `N sessions still queued / still priming`

The cost cache primes over several passes with a byte budget per pass. Sessions it defers keep
the number they already had and are labelled `[queued]`. Run the command again.

### Stale pidfile, or the supervisor will not start

```sh
$OE/bin/oe supervise --status     # what it thinks is running
$OE/bin/oe supervise --stop
$OE/bin/oe supervise --ensure
```

`--ensure` decides the race with a flock, not with the pidfile, so a stale
`state/supervisor.pid` cannot produce two supervisors. If `--status` reports
`"running": true` for a pid that no longer exists, `--stop` clears it.

### The context index is wrong or corrupt

```sh
$OE/bin/oe find --stats            # counts and size
$OE/bin/oe index --full <root>     # re-parse everything under a root
rm $OE/state/context.db            # next open builds a clean one
```

A corrupt database is renamed to `context.db.corrupt-<stamp>` and rebuilt automatically; you
do not have to catch it.

### The reports look stale

```sh
$OE/bin/oe rebuild --all --purge   # regenerate every artifact through the allowlist
$OE/bin/oe audit --all             # prove the result is shareable
```

Reports are pure derived data — deleting and regenerating them loses nothing. **State is
not**: `state/session-map.json` is the only thing that maps a report pseudonym back to a real
session, and it cannot be recomputed. `--purge` never touches it, because state lives outside
the reports tree.

### A hook entry points at a file that is gone

If a settings file still registers a hook whose script has been deleted — a checkout removed
without uninstalling, or a partial upgrade — Claude Code reports the error on the event that
fires, which for a tool-call hook is every tool call. `bin/oe-repair` exists for exactly that
state and deliberately **imports nothing from `oe/`**, so it still runs when the package
itself is broken:

```sh
python3 $OE/bin/oe-repair        # names every registration pointing at nothing
python3 $OE/bin/oe-repair --all  # also examines entries belonging to other tools
```

**v1.0.2 diagnoses only.** `--yes` is accepted, refused, and explained. The repair path is
held back one release because it can remove a registration that is *working*: it resolves
`$CLAUDE_PROJECT_DIR` and relative hook paths against whichever directory you are standing
in, and it reads the subcommand of a wrapper (`uv run x.py`, `npx tsx x.ts`) as the script
name. Deleting a live `PreToolUse` entry stops every tool call in every session on the
machine — a worse outcome than the fault being repaired. Apply the printed plan by hand;
every change is quoted line by line, and taking a copy of the file first costs nothing.

`oe repair` runs the same tool as a subprocess and passes every flag straight through, so it
is reachable by the name you already know when `oe` itself still starts.

With no argument it checks the nearest project settings file above the current directory;
`--settings <path>` checks exactly one file, `--root` says which checkout counts as "ours",
and `--json` prints the verdict as fields. `--all` is off by default because silently deleting
somebody else's integration is worse than reporting it.

**Its output is not redacted.** It imports nothing from `oe/`, so it has no redactor: it
prints absolute paths, including yours, exactly as they appear in the settings file. That is
the one exception to [the redaction policy](privacy.md), and it is the price of a rescue tool
that still works when the rest of the checkout does not. Read what it printed before you
paste it into an issue.

### Something is about to be pasted into a ticket

Piped output is already redacted. If you are copying from a terminal, ask for it explicitly:

```sh
oe sessions --redact
```

## What it writes and where

```
oe/paths.py       paths, config, atomic writes, DEFAULT_CONFIG
oe/pricing.py     the model catalog and the exact cost formula (generated)
oe/ledger.py      transcript parsing, the incremental cost cache, the cheap scan
oe/report.py      report.html / data.json / summary.md / calls.csv (14 sections)
oe/dashboard.py   index.html across sessions
oe/watcher.py     per-session watcher, the supervisor, the new-session scan and
                  the placeholder report
oe/autostart.py   the OPTIONAL shell-rc block: bash + zsh, macOS + Linux
oe/checklist.py   the dependency checklist install.py and `oe doctor --install` print
oe/statusline.py  the optional in-window row
oe/store.py       the context index: symbol-aligned FTS5 chunks, symbols, import edges
oe/retrieval.py   `oe find` / `oe slice` / `oe deps` / `oe index`
oe/accounts.py    self-configuring account labels (no address in any shipped file)
oe/redact.py      the allowlist for artifacts AND the CLI redaction policy
oe/package.py     `oe package`: the shareable-bundle allowlist and its leak scan
oe/manifest.py    the install manifest: what a run touched, and whether it is
                  still what we left -- what makes --uninstall exact
oe/version.py     the version, and the commit it came from (`oe version`)
bin/oe            the CLI
bin/oe-watch      one-word shim for `oe watch`
bin/oe-repair     the standalone rescue script. Imports nothing from oe/, so it
                  still runs when the package is broken or missing
hooks/            the three optional hook scripts
install.py        the ONLY file here that writes settings.json (with install-statusline)
extract_pricing.py  regenerates the pricing table from the binary

VERSION           the release number, one line. A release tag is `v` + this,
                  and the release workflow refuses a tag that disagrees.

config.example.json  the configuration reference, at its code defaults. TRACKED.
config.json          your copy of it. NOT tracked, and optional.

.gitignore        an ALLOWLIST: deny everything, re-admit exactly what ships
.gitattributes    LF everywhere, so bin/oe survives a clone on a CRLF machine
LICENSE           MIT
CONTRIBUTING.md   the two hard constraints, what is never committed, the pre-push gate
SECURITY.md       where to report a vulnerability, and which classes are wanted
.github/workflows/ci.yml       compile / checklist / leak gate, on every push and PR
.github/workflows/release.yml  on a `v*` tag: tag-vs-VERSION, compile, leak gate,
                               `oe package`, publish the release
.github/scripts/leak_gate.py   the CI half of the leak gate: shapes + the tracked file list

state/            local, never shareable -- neither `oe package` nor git can include it
reports/          only if you point reports_root inside the checkout; never tracked
```

### Where the output lands

```
<reports_root>/
  index.html                      cross-session dashboard
  sessions.json                   the same rows as machine-readable JSON
  sessions/<session-id>/
    report.html                   the per-session report (14 sections)
    data.json                     everything the report was rendered from
    summary.md                    the same report as markdown
    calls.csv                     one row per API request, 40 columns
    row.json                      the kilobyte-sized row the scan reuses
    meta.json                     only with the hooks: start/end timestamps

$OE/state/
  install-manifest.json           every settings file an install touched: checksums,
                                  backups, scope -- what --uninstall reads first
  settings-baseline.<id>.json     the byte-exact settings file from before the FIRST install
  bin-link.json                   the `oe` symlink this install created
  session-map.json                pseudonym -> real session id, title, transcript
  session-map.json.bak            one rolling backup, written before every replace
  session-map.lock                the flock that serialises pseudonym allocation
  legacy-session-map.json         only on a machine that had a pre-migration .state:
                                  the pre-merge copy, kept rather than deleted
  accounts.json                   which account each session was billed to
  accounts.lock                   the flock beside it
  cost-cache/<session-id>.json    the incremental parse cache
  context.db                      the context index
  agent-prior.json                how read-heavy the last few finished subagents were,
                                  refreshed by SessionEnd and read by the spawn hook
  agent-brief.ndjson              one line per brief actually injected: when, how many
                                  tokens, how many files. Written only while
                                  `brief.enabled` is true
  <session-id>.live.json          the snapshot the status line reads
  <session-id>.injector.json      the budget line's per-session rate-limit state
  supervisor.{pid,lock,json,log}  the daemon
  watcher-<id>.log                per-session watcher logs
```

The state directory is **not** configurable through `config.json`, and is deliberately not
inside the reports root — see [The artifacts](privacy.md#the-artifacts). `OE_STATE_DIR`
relocates it for a test harness.

### How the numbers are produced

One API request spans many JSONL lines (one per content block) and is deduped by `requestId`.
Subagent transcripts live in `<session-id>/subagents/agent-*.jsonl` and, nested,
`<session-id>/subagents/workflows/wf_*/agent-*.jsonl` — often far more bytes than the main
transcript, so anything that reads only the main file under-counts.

The live view therefore does not tail. It keeps an **incremental cost cache**
(`state/cost-cache/`): each file is fully parsed once, and later passes read only the bytes
appended since. A cold cache primes over several passes with a byte budget per pass; sessions
it defers keep the number they already had and are labelled `[queued]`.

The moment a transcript appears the supervisor writes a **placeholder** `report.html`,
`data.json`, `summary.md` and `row.json`, then hands the session to the ordinary discovery
path. The placeholder carries a short `<meta refresh>`, states no figures (no `$0.00` that
could be read as a measurement), and deliberately carries **no `schema_version`** — the key
`ledger` checks before it will believe a cached number, so a placeholder can never be mistaken
for measured data.

## Repository CI and licence

### `.gitignore` is an allowlist, and that changes how you add a file

`.gitignore` denies everything with `*` and re-admits exactly what ships, by name — the same
rule `oe package` uses, because a denylist ships whatever nobody thought to exclude and the
thing nobody thinks to exclude is `state/`.

The consequence will surprise somebody: **a newly added file is invisible to `git status` and
silently skipped by `git add`, with no error.** To make a file part of the repository you name
it in two places — `.gitignore`, and `ROOT_FILES` or `TREES` in `oe/package.py`. Those two
lists disagreeing is itself a finding, and `oe package` reports it (`package.drift`).

`.gitattributes` sets `* text=auto eol=lf`, with explicit rules for `bin/oe` and `bin/oe-watch`:
those two are extensionless scripts whose first line is a shebang, and a clone with
`core.autocrlf=true` turns `#!/bin/sh` into `#!/bin/sh\r`, which surfaces as `oe: not found`
with nothing pointing at the cause.

### CI, and exactly how much a green build proves

Three jobs run on every push to `main` and every pull request, and each is a command you can
run locally: `compile` (byte-compile the tree on the oldest and newest interpreters claimed,
plus one macOS leg), `checklist` (`install.py --check --allow-missing-claude
--no-binary-probe`, then an assertion that the working tree is unchanged — which is what makes
"`--check` writes nothing" a tested claim rather than a promise), and `leak-gate`
(`.github/scripts/leak_gate.py --require-git`). `release.yml` runs on a `v*` tag only and
repeats them, because a tag can point at a commit neither `main` nor a pull request ever saw.

**What the leak gate does and does not prove.** It checks that nothing forbidden appears in
`git ls-files` — `.gitignore` does nothing at all about a file that is already tracked, so the
tracked list has to be asserted directly — and then runs the **shape tier** of `oe package`'s
scan: a machine-independent sweep for `/home/…` and `/Users/…` paths, email addresses, uuids,
branch names and issue keys.

It deliberately does **not** run the identity tier. That tier matches the real username, email
and hostname of the machine running it, and on a hosted runner that machine is an ephemeral VM
whose identity this repository could not possibly contain — so the check has no authority
there, and is also actively wrong: a runner's `$USER` is `runner`, a word that appears in
`oe/redact.py`'s own generic-account list and in this file. **The identity tier only has
authority on a maintainer's machine, and `oe package` is where it runs.** `CONTRIBUTING.md`
makes that a pre-push requirement, because nothing mechanical can.

And neither tier can see an employer name, a product name, a repository name or a source-file
basename. None of those is shaped like anything. A green build means "no forbidden file is
tracked and nothing published is PII-*shaped*" — it does not mean "safe to publish". A human
read is the only control for that category.

### Reporting something

For an ordinary bug or a question, open an issue. One instruction that is easy to get wrong:
**`oe` redacts automatically only when stdout is not a terminal.** So `oe doctor | cat >
doctor.txt` is redacted and safe to attach, and a screenshot of the same command is not,
because stdout was a terminal. `--redact` forces it either way.

For anything that looks like a vulnerability, do not open a public issue — see
[SECURITY.md](../SECURITY.md), which names the classes that are actually wanted here: personal
data that survives `oe audit` or `oe package`, a way for transcript contents to influence what
a hook executes, `install.py` writing outside the file it named, and a path that escapes
`reports_root()` or `state_dir()`.

To change something, [CONTRIBUTING.md](../CONTRIBUTING.md) has the two hard constraints (stdlib
only; zero config by default), the never-commit list, and the commands to run before you push.

### Licence

MIT — see [LICENSE](../LICENSE).

That licence covers this tool. Claude Code itself is Anthropic's, and what this repository
records about its hook contract and its pricing tables is **observed behaviour** — read out of
a build that was installed on the machine this was written on — not a grant of anything from
Anthropic. Nothing here should be read as implying otherwise.
