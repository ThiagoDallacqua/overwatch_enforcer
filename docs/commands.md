# Command reference

*Part of the Overwatch Enforcer documentation. [← README](../README.md)*

## About the examples

**Each block below shows how to invoke the command, not what it prints.**

v1.0.0 ships no captured sample output. The blocks that used to be here were produced by a
fixture whose generator was never committed, which meant nothing could check that the figures
in them came from that fixture rather than from a real session — and this project does not
ship a number it cannot account for. Rather than ask you to take that on trust, the output is
gone until it can be regenerated from a fixture that ships with the tool and is verified on
every build. That is planned for v1.0.1.

Run any command below against your own sessions to see its real output. Piped or redirected,
every command redacts by default ([Privacy](privacy.md)): `session_01`, `project_01`, `-` for
titles. On a terminal you see real ids, paths and titles.

## Live and per session

### `oe` / `oe status [session]`

The full breakdown of one session. With no argument it takes the current one (`--last`
takes the most recent). `--fast` is tail-only, `--json` gives the same figures as fields,
`--all-accounts` switches to a per-account rollup.

```
$ oe status 3f5c1a90
```

`no timing` in the tool table is not a fault: wall time per tool call exists nowhere in the
transcript, so no session has it. See [Known limits](operations.md#known-limits).

#### The cache residency block

The `cost by token kind` table says how many dollars went on cache reads. It cannot say
whether that was one enormous request or a thousand ordinary ones, and those call for
opposite responses. `cache residency` answers the second question, because every request
re-sends the whole prefix and a session's bill is therefore prefix size times request count.

* **per request** — what one request pays to re-send your window before it does any work.
* **per message** — the median turn. Turns that only spent their budget on agents are left
  out, and the median rather than the mean, so one large fan-out does not set the figure for
  every ordinary turn. Shown once there are at least three turns to take a middle of.
* **next request** — the marginal figure: what the window resident right now would cost to
  re-send. Priced at this session's own realised rate, so it already carries whatever tier,
  region and model the session actually used, rather than a rate looked up from a table.
* **per window fill** — appears once the window has emptied at least once. Filling a context
  window is the unit of work this tool can price; this is the average cost of one.
* **agent windows** — appears when agent context is at least a twentieth of the cache-read
  bill. Subagent and workflow windows are re-sent too, and they are not your window.

Three cautions, all of which the block states in its own words or inherits from the total
above it. Every figure is derived from the session in front of it and none is a target or a
threshold. All are floors: a subagent-heavy session reads under the billed figure, because a
sidechain transcript never writes back its final usage record. And `next request` is a floor
in a second way — a prefix that has fallen out of cache is re-*written* rather than read,
which costs more.

The same per-turn figure is the `Re-read` column of section 07 of the HTML report.

### `oe watch`

The live view of every open session, redrawing on an interval, and it keeps the per-session
HTML reports building while it runs. This is the command to run if you run only one.
`--once` draws a single frame and exits, which is what a pipe does anyway; `--inline` runs
the supervisor inside this process so it stops with the view; `--no-supervisor` shows
existing data only.

```
$ oe watch --once --no-supervisor
```

Below the session rows it prints a supervisor status banner and a key legend
(`q quit  r refresh  o report  d dashboard  ? help`). `--no-supervisor` runs it without
leaving a daemon behind; a plain `oe watch --once` prints the same thing and starts one.

### `oe sessions`

One row per session across every project. `--active`, `--days N`, `--limit N`, `--json`, and
`--account <label>`.

```
$ oe sessions
```

(The `PROJECT` and `TITLE` columns do not line up here because the redacted pseudonyms are a
different length from the values the column was padded for. On a terminal, unredacted, they
line up.)

### `oe report` / `oe path` / `oe open`

`report` builds the artifacts now and prints where they went. `path` prints the location
without building — it is derived from the session id, so it is stable. `open` launches the
HTML in a browser. All three take a session id, an id prefix, a path, or `--last`.

```
$ oe report 3f5c1a90
```

```
$ oe path 3f5c1a90
```

`report.html` has 14 sections: headline, context window, spend over time, cost by token kind,
by model, main loop vs agents, per turn, tool usage, cache efficiency, reconciliation against
Claude Code, optimisation opportunities, the re-read ledger, ledger findings, and the raw API
requests. `summary.md` is the same report as markdown, `calls.csv` is one row per API request
in 40 columns, and `data.json` is everything the report was rendered from.

### `oe dashboard` / `oe backfill`

`dashboard` rebuilds the cross-session `index.html` and `sessions.json`. `backfill` builds
reports for past transcripts that do not have one yet; `--force` rebuilds even the current
ones, `--all` covers every transcript on disk and `--days N` narrows it.

```
$ oe dashboard
```

```
$ oe backfill --all --force
```

Without `--force`, a session whose report is already current is skipped
(`built 0, skipped 3, failed 0`).

## Where the money goes

### `oe rereads [session|--all]`

Every file read in a session, classified and priced: how many times it was read, across how
many context windows, and how much of that was avoidable. `--limit N` sets the number of file
rows, `--measured` ranks by this session's own carry cost instead of the configured
calibrated rate, and `--json` gives the rows as fields.

```
$ oe rereads 3f5c1a90
```

The two money columns answer different questions. **calibrated** prices a repeat at
`insights.carry_usd_per_1k` ([Configuration](configuration.md#configjson)) — a fixed
forward-carry rate, so the number is comparable across sessions. **measured** prices it at
this session's own realised carry, which is the honest figure for this session and moves with
it. Neither is a saving you can bank: a repeat read in a *different* context window was never
recoverable, and the `windows` column is what tells you which kind you are looking at.

**This command prints file basenames even when piped.** It is one of the four that do; see
[The retrieval exception](privacy.md#the-retrieval-exception).

### `oe savings [session|--all]`

Every lever the tool can measure on your own data, ranked by dollars, each with the setting to
change and what to do. `-v` prints the arithmetic behind each row.

```
$ oe savings --all
```

Rows sharing a group monetise the same tokens, so the total is deliberately **not** the sum of
the rows: `levers not yet taken` counts the largest row in each group once. The `do:` text is
clipped to the terminal width; widen the terminal to read it in full.

## Retrieval

These four commands exist so an agent can be handed a slice instead of a file path. They read
a local SQLite index at `state/context.db` (relocate it with `OE_CONTEXT_DB`) that stores
**symbol-aligned** chunks — a function, a class, a markdown heading section — so a hit is a
usable slice rather than a windowed fragment.

FTS5 is required, with native `bm25()` ranking. The table is contentless, so the source text
is never copied into the database, only the inverted index. That is what keeps it small, and
it is why `snippet()` is unavailable — snippets are cut from the file on disk, which is the
correct behaviour anyway, since a cached snippet could show text an edit has already
invalidated. Every public entry point **fails open**, and a corrupt database is renamed aside
to `context.db.corrupt-<stamp>` and rebuilt rather than raised.

### `oe index [roots…]`

Incremental: only files whose mtime or size changed. With no argument it re-scans the roots of
the last index run. `--full <root>` re-parses everything under that root.

```
$ oe index --full acme
```

There is no separate "rebuild the store" command because there does not need to be: the index
is incremental and cheap, and `rm $OE/state/context.db` is a supported recovery — the next
open builds a clean one.

### `oe find <query>`

bm25-ranked slices from the index.

```
$ oe find "retry backoff"
```

The footer is computed at run time from what was actually printed against what reading those
files whole would have cost. It is a real ratio for that query on that index, not a claim
about anybody else's.

`--stats` prints the index itself as JSON instead of searching:

```
$ oe find --stats
```

### `oe slice <path> [symbol|lo-hi]`

One symbol, one line span, or — with no second argument — the file's outline.

```
$ oe slice acme/src/http/retry.ts withRetry
```

```
$ oe slice acme/src/http/retry.ts
```

### `oe deps <path>`

The import subtree as a ranked slice. The resolver is regex plus a `provides` table, so
`using X;` and `from x import y` resolve like a relative import.

```
$ oe deps acme/src/http/client.ts
```

By default `deps` prints only paths, symbol names and token counts; `--body` adds the source
of each chunk. `--depth N` bounds the walk, `--in` reverses it to "who imports this", `--both`
does both directions, `-k N` caps the chunks returned and `--max-tokens N` caps the output.

**`oe find` prints one line of each chunk it matched, and `oe slice` (and `deps --body`)
print the source itself — verbatim, piped or not.** Redacting them would delete the answer.
Treat them the way you would treat `cat`:
[The retrieval exception](privacy.md#the-retrieval-exception).

## Accounts, privacy and artifacts

### `oe account`

Labels self-configure: the first account the tool ever sees becomes `primary`, the next
`secondary`. `list` shows the split, `whoami` names the account logged in right now, `rename`
changes a label everywhere, and `assign` / `unassign` override a session by hand.

```
$ oe account list
```

```
$ oe account whoami
```

Provenance is labelled, never guessed silently: `recorded` is the transcript's own
bridge-session owner id, `inferred` is a low-confidence hint printed with its evidence, and
`unknown` means nothing on disk names an account. A transcript with no bridge record reports
`unknown` even while the live login is known.

### `oe audit [session|--all]`

Re-scans the written reports for personal data and exits non-zero on any finding. This is the
command that answers "is this directory safe to send?".

```
$ oe audit --all
```

### `oe whois <pseudonym>`

Maps a report pseudonym back to the real session. **Local only** — the map that makes this
possible lives in `state/`, never in the reports tree.

```
$ oe whois session_01
```

Piped, as here, the answer is itself redacted — which is the right default, since piping is
what you do before sharing. On a terminal it prints the real id, project and transcript path,
which is the whole point of the command.

### `oe rebuild [session|--all] [--purge]`

Regenerates every artifact through the redaction allowlist. `--purge` deletes the old
artifacts first, including report folders whose transcripts are gone.

```
$ oe rebuild --all
```

Reports are pure derived data — deleting and regenerating them loses nothing. **State is
not:** `state/session-map.json` is the only thing that maps a pseudonym back to a real
session and it cannot be recomputed. `--purge` never touches it, because state lives outside
the reports tree.

### `oe package`

Builds a shareable bundle of the tool itself, and refuses to write one if it would leak.
`--dir` leaves a staged directory instead of an archive, `--out` names the archive, `-v` lists
every file and every accepted placeholder, `--json` gives the findings as fields.

It ships an allowlist, rewrites `config.json` to the code defaults, re-scans the staged copy
for this machine's real identity, and scrubs your username out of the tar headers. A clean run
writes the archive; any unreviewed personal-shaped string is printed with its file and offset
and **no archive is written**. See [Sharing the tool itself](privacy.md#sharing-the-tool-itself).

## Health and background

### `oe doctor`

Verifies the install. Exit 0 means the primary path is healthy; the optional extras are
reported and never fail the check. `--no-pricing` skips the read of the Claude Code binary
when you just want the fast answer, and `--install` adds the dependency checklist.

```
$ oe doctor --no-pricing
```

Below the primary path, `oe doctor` prints two optional sections — the in-window status line
and the hooks — each of which is reported and never fails the check.

### `oe install-statusline` / `oe uninstall-statusline`

The optional in-window row. This is the one feature that cannot work without a `settings.json`
key, because `statusLine` is Claude Code's only extension point for a row inside its window.
It is a dry run unless you pass `--yes`, and it prints the exact diff:

```
$ oe install-statusline
```

What it renders, driven directly with a Claude Code status payload:

```
$ python3 oe/statusline.py <<'JSON'
{"session_id":"3f5c1a90-2d44-4b71-9c0e-7a1b6d820e11","cwd":"/srv/acme","model":{"id":"claude-opus-5[1m]","display_name":"Opus 5"},"cost":{"total_cost_usd":2.72,"total_duration_ms":6840000},"context_window":{"used_tokens":154439,"max_tokens":1000000}}
JSON
```

The trailing word is the freshness of the snapshot the row is reading: `live` while a watcher
is writing it, `stale` with its age when nothing has updated it recently.

### `oe supervise --ensure | --status | --stop`

Starts, inspects or stops the background writer. `--ensure` decides the race with a flock, not
with the pidfile, so a stale `state/supervisor.pid` cannot produce two supervisors.
`--status` prints JSON: whether it is running, its pid and the paths of its pidfile, lockfile,
status file and log, plus a snapshot of its own timings and what it is tracking.

### `oe autostart --status | --install | --remove`

The optional one-line shell-rc block that starts the supervisor at login. It never touches
`settings.json`. See [the autostart block](install.md#the-optional-autostart-block) for what it
writes and what it costs.

### `oe prune`

Drops residency, events and per-session scratch older than N days, then VACUUMs. It is a dry
run — counts only — unless you pass `--yes`.

```
$ oe prune
```

### `oe reprice`

`oe/pricing.py` carries the model catalog transcribed from the Claude Code binary, and
`oe doctor` re-extracts it from the newest installed binary and **fails if they disagree** —
a stale table makes every dollar on the screen wrong. `oe reprice` rewrites the generated
block from the binary and leaves a `oe/pricing.py.bak` beside it. The cost cache records the
pricing version it was built with and discards itself when that changes, so old dollars
computed at old rates are never mixed in; expect `N still priming` for a few runs afterwards.

### `oe version`

The first line of any bug report. `oe --version` and `oe -V` print the same thing, and
`--json` gives it as fields. See [Pinning a version](install.md#pinning-a-version).

## The budget line

`hooks/user_prompt_submit.py` puts one compact line on the screen, once per prompt. Driven
directly with a Claude Code prompt payload:

```
$ python3 hooks/user_prompt_submit.py <<'JSON'
{"hook_event_name":"UserPromptSubmit","session_id":"3f5c1a90-2d44-4b71-9c0e-7a1b6d820e11","cwd":"/srv/acme","prompt":"add a retry to the fetch helper"}
JSON
```

The two halves of a hook's reply are not the same thing and cost different amounts.
**`systemMessage` is free**: the CLI renders it and it never enters the request.
**`hookSpecificOutput.additionalContext` is the half the model reads, and it is charged** — a
token placed in the window is re-sent as a cache read on every subsequent request for the rest
of the session, so a line emitted on every prompt is paid for on every prompt after it too.

So the injector is **silent by default**: no finding, no `additionalContext` key at all, which
is what the run above shows. When it does have something to say it is rate-limited, and the
one-line retrieval hint naming `oe find` / `oe slice` / `oe deps` is emitted **once per
session** and then retired. `OE_INJECTOR_SCREEN` controls what goes on screen.

`hooks/session_start.py` emits an `additionalContext` line of its own, once per session,
naming the same three retrieval commands.
