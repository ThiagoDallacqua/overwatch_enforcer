# Privacy

*Part of the [Overwatch Enforcer](../README.md) documentation. [← README](../README.md)*

The written reports have always been allowlist-built and audited. The **terminal** was the
gap, because a terminal is what gets screenshotted into a ticket and pasted into a chat. So
there is one policy:

```
stdout IS a terminal      ->  you are reading it yourself; full detail.
stdout is NOT a terminal  ->  it is piped, redirected, captured or copied; REDACT.
```

**Piped output is redacted by default, because piped output gets shared.** A stream whose
`isatty()` raises is treated as not-a-tty — it redacts, which is the safe direction.

Every `oe` command follows that policy, `--json` included. There are two carve-outs, both
deliberate:

* File *contents*: `oe find` and `oe slice` exist to print the source at a path, and
  redacting that would delete the answer. See
  [The retrieval exception](#the-retrieval-exception).
* `bin/oe-repair`, which `oe repair` runs as a subprocess. It imports nothing from `oe/` —
  that is the whole point of it, because it has to work when `oe/` is gone — so it has no
  redactor and prints absolute paths verbatim. **Read its output before pasting it
  anywhere.**

## The controls

| control | values | precedence |
|---|---|---|
| `--redact` / `--no-redact` | flags, valid in any position on the command line | 1 (highest) |
| `OE_REDACT` | `1`/`true`/`on`/`always`/`redact` vs `0`/`false`/`off`/`never`/`raw` | 2 |
| `config.json` → `redact_cli` | `auto` \| `always` \| `never` | 3 |
| the default | `auto` = redact whenever stdout is not a tty | 4 |

```sh
oe sessions --redact          # redact even on a terminal (screen sharing, recording)
oe sessions --no-redact       # full detail even when piped (a local file you will read)
OE_REDACT=always oe sessions
```

Any other `OE_REDACT` value, including `auto`, defers to `config.json`.

## What is redacted

Enforced by wrapping `sys.stdout` / `sys.stderr` in a line-buffered scrubbing stream and
replacing `sys.excepthook` — not by editing every `print()`. A policy that thousands of lines
have to remember leaks the first time somebody adds a line, and a **traceback** quoting an
absolute home path is a leak no `print()` audit would have caught. Line buffering is
load-bearing: `print()` emits the text and the newline as separate `write()` calls, so
scrubbing per-write would miss an identifier split across the boundary.

Ordered rules — project slugs first, because the home and username rewrites would otherwise
destroy the exact-match lookup:

| in the raw output | redacted to |
|---|---|
| a project path, slug, or its last path segment (the repo name) | its report pseudonym (`project_01`) |
| your home directory | `~` |
| anyone else's `/home/x`, `/Users/x` | `/home/<user>`, `/Users/<user>` |
| the username as a bare token, anywhere (`<name>-laptop`) | `<user>` |
| the hostname, and its short form | `<host>` |
| an email address of one of your logins | the account **label** only (`<account:primary>`) |
| any other email address | a short one-way hash (`<email-1a2b3c4d>`); the address is never stored |
| a session uuid | its report pseudonym (`session_07`), or a stable short hash |
| a truncated session id in a table cell | its pseudonym |
| a branch name (`feature/…`, `fix/…`, `hotfix/…`, `chore/…`, `release/…`, `bugfix/…`) | `<branch>` |
| a ticket id | `<ticket>`, unless it is a known-safe shape (a model id, a CSS token, a charset) |
| an IPv4 address | `<ip>` |
| a session **title** or **last prompt** in a rendered table | `-` / `(title hidden)` |

Two deliberate narrowings, both of which make the tool usable rather than just quiet:

* **Generic account names are never substituted.** `root`, `user`, `admin`, `ubuntu`,
  `runner`, `dev`, `app`, `test`, `node`, `www`, `ci`, `build`, `docker`, `vagrant` and about
  twenty more are on a stop list. Those names identify nobody, and as needles they matched
  the tool's own hardcoded HTML (`:root{`) and ordinary English. Without this exemption the
  redaction gate refuses to write a report at all inside a container or a CI image.
* **A username must sit on an identifier boundary to match.** Every realistic leak shape —
  `/home/<name>/…`, `<name>@…`, `<name>s-laptop`, a bare mention — still matches. A username
  glued mid-token with no separator on its left (`x<name>y`, or camelCase) does not. Short
  names additionally need a boundary on the right, so a three-letter username matches
  `/home/ana/x` but not `analysis` or `banana`.

The redacted form is not lossy in the way that matters: the pseudonyms are the same ones the
reports use, so a redacted terminal row and a report page name the same session.
`oe whois session_07` maps one back, locally.

## JSON output

Every `--json` emitter runs through **the same field-by-field allowlist that builds the
artifacts**, under the same policy as the stream scrubber. That matters because the scrubber
removes identifiers by *shape*, and a prompt, a session title and a shell command line have
no shape — they would sail straight through it.

So `oe status --json | tee bug.json` and the `data.json` in the reports tree carry exactly the
same fields. The top-level keys of a redacted `oe status --json`, and its `session` sub-object,
contain no prompt, no title, no cwd, no branch and no transcript path:

```
$ oe status 3f5c1a90 --json | python3 -c "import sys,json;d=json.load(sys.stdin);print(sorted(d));print(sorted(d['session']))"
['agent_type_costs', 'by_model', 'by_origin', 'by_tool', 'by_turn', 'cache_efficiency', 'calls', 'calls_truncated', 'compactions', 'context_growth', 'context_series', 'context_window', 'cost_series', 'expensive_agents', 'expensive_turns', 'generated_at', 'insights', 'parse', 'reconciliation', 'redaction', 'redundant_work', 'rereads', 'schema_version', 'session', 'tools', 'tools_truncated', 'top_calls', 'totals', 'waste', 'workflows']
['account_label', 'account_source', 'agents', 'cc_version', 'id', 'last_activity', 'primary_model', 'project', 'started_at', 'turns', 'wall_seconds', 'workflows']
```

A terminal, or `--no-redact`, still gets the raw payload — including the fields that are
dropped above.

## The retrieval exception

`oe slice` prints **file contents byte-for-byte verbatim, piped or not**, and so do `oe find`
(one line per matched chunk) and `oe deps --body`. That is the exception, it is deliberate, and
there is no fix that keeps the command useful. A slice of your source is your source: if it
holds a key, a customer name or an internal URL, so does the output. **Before you paste one of
those into a public issue, read it.**

Paths and basenames are a different case, and it is worth being exact about the difference.
**Paths go through the ordinary redaction rules like everything else.**
A file called `ABC-913-notes.ts` prints as `<ticket>-notes.ts`:

```
$ oe find "AES GCM"
1 acme/tickets/<ticket>-notes.ts:1-3  AES_256_GCM ABC_913 [const]  19 tok
   export const AES_256_GCM = "aes-256-gcm";
-- 1 hits / 1 files | printed 29 tok = 152.6% of 19 tok whole-file (0.7x cheaper) | full spans would be 19 tok = 100.0%
-- paths relative to ~
```

The header is redacted; the body line under it is the file. That is the policy working, and
it has one consequence worth naming: **a redacted path cannot be pasted back into `oe slice`.**
When a basename trips a rule, the `find` → `slice` round trip needs `--no-redact` (or a
terminal) to give you a path you can use.

`oe rereads` is the third command whose whole output is filenames, and it follows the same
rule: paths redacted, and the table is the answer, so read it before you share it.

**A second boundary, about categories rather than commands.** Both the CLI redactor and
`oe package`'s scan work on *shapes* and on *this machine's identity values*. An employer
name, a product name, a repository name and a source-file basename are none of those — they
are ordinary words. So a clean `oe package` means "this carries no account identity of mine
and nothing shaped like personal data"; it does **not** mean "this names nobody I work for".
Nothing automated covers that category, here or anywhere else in the tool, and a human read
of anything you publish is the only control there is.

## The artifacts

The reports tree is built from an **allowlist**, not a denylist: every artifact is
reconstructed field by field, so a field added to the ledger later is dropped until it is
named on purpose in `oe/redact.py`. `oe audit` re-scans what was written and exits non-zero on
any finding.

The `state/` directory is deliberately **not** inside the reports root. The reports root is
the folder you hand to somebody else, and `session-map.json` alone turns every `session_NN` in
it back into a real id, title and transcript path. Nesting the two would make
`tar -czf report.tgz .` ship the key with the lock. `oe doctor` asserts the separation, and
`oe audit` fails on a `.state/` found inside a reports tree.

## Sharing the tool itself

`oe audit` answers "are these **reports** safe to send?". It says nothing about the directory
the tool lives in — which holds `state/`, and therefore the key to every pseudonym those
reports use.

**Send the repository link, or build a bundle with `oe package`. Never copy the directory.**

* A clone is safe because the repository tracks neither `state/` nor `config.json`, and
  `.gitignore` is an allowlist, so a file nobody thought about is excluded by default rather
  than included by default.
* A bundle is safe because `oe package` ships an allowlist, rewrites `config.json` to the code
  defaults, re-scans the staged copy for this machine's real identity, and scrubs your
  username out of the tar headers — refusing to write an archive at all if any of that fails.
* A hand copy has none of those properties: it carries `state/`, your `config.json`,
  `__pycache__`, and whatever else is lying in the tree.
