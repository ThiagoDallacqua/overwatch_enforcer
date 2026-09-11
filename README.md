# Overwatch Enforcer

A token, cost and context meter for Claude Code. It reads the JSONL transcripts Claude Code
already writes to your disk and turns them into per-session reports, a live view, and a
ranked list of where the spend is going. It also indexes your source so an agent can be
handed a slice instead of a whole file.

Python 3.10+, standard library only. No packages, no network, no account.

> **Early development.** `v1.0.2` is the current release and the tool is in real use, but it
> is still moving: command names, flags and the shape of what they print can change between
> releases. If you need it to stay still, install a tag rather than `main`
> ([Pinning a version](docs/install.md#pinning-a-version)). Bugs are expected. The exposure is not
> open-ended, and it is worth knowing exactly what it is:
>
> * **It reads, and it never sends.** Every number comes from files Claude Code already
>   wrote. No command in this tool opens a socket.
> * **`install.py` is the only file that writes a Claude Code settings file, and only with
>   `--yes`.** It backs the file up and verifies the copy first, and `--uninstall` takes out
>   exactly what was put in ([Uninstall](docs/install.md#uninstall)).
> * **Some totals are floors, not exact figures.** Subagent-heavy sessions compute under the
>   billed number, because the final usage record of every subagent request is missing from
>   disk. Those figures print with a leading `~` and the label `[measured]`
>   ([Known limits](docs/operations.md#known-limits)).
>
> Reporting a bug: open an issue with the output of `oe version` and `oe doctor | cat`
> (piping is what makes it redacted), and what you expected instead.

## Install

```sh
git clone https://github.com/ThiagoDallacqua/overwatch_enforcer
cd overwatch_enforcer
python3 install.py
```

The repository is named `overwatch_enforcer`, with an underscore, so that is the directory
`git clone` creates and the one to `cd` into. The install root is derived from `__file__`,
so nothing depends on the directory's name or where it lives — rename or move it freely.

`python3 install.py` prints a dependency checklist and then a **dry run**: the exact diff it
would make to one settings file. It writes nothing until you re-run it with `--yes`.
`python3 install.py --check` is the checklist alone and creates nothing, not even a
directory. [Install](docs/install.md) has the detail, including which settings scope to pick.

Two things worth knowing on either side of that command:

* **Before.** The installer backs your settings file up and verifies the copy, but a manual
  copy of your own does not depend on this tool being correct, and it is one line:
  [Back up your settings file](docs/install.md#back-up-your-settings-file).
* **After.** If a fresh terminal answers `oe: command not found`, that is PATH and not a
  failed install. `python3 install.py --path-doctor` says which of five reasons it is, and
  `--path-fix --yes` cures it: [If oe is not found](docs/install.md#if-oe-is-not-found).

**What it costs to run: nothing.** No packages, no virtualenv, no lockfile, no build step,
no account, no network. The measurement half needs no install step at all — `./bin/oe watch`
works in a fresh clone with nothing registered anywhere. `install.py` exists for the three
optional hooks and the status line, and it is the only file here that writes `settings.json`.

MIT licensed. Linux and macOS; see [Shells and platforms](docs/install.md#shells-and-platforms)
for what is verified where.

If Claude Code stops with a hook error, repair it from a plain shell:

    python3 <checkout>/bin/oe-repair          # names every broken registration

It **diagnoses only** in v1.0.2 and never writes: it prints the entries that
point at nothing, quoted line by line, and you remove them by hand. The repair
path is held back one release because it can delete a registration that is
working — see [A hook entry points at a file that is gone](docs/operations.md#a-hook-entry-points-at-a-file-that-is-gone).

`oe repair` runs the same tool. It imports nothing from `oe/`, so it still
works when the rest of the checkout does not — which is the state it is for.
Its output is deliberately NOT redacted: read it before pasting it anywhere.

## The two layers

**Measurement — zero configuration.** Nothing is installed and nothing is registered.
Everything is derived from `~/.claude/projects/**/*.jsonl`, which Claude Code writes whether
or not this tool exists. `oe status`, `oe watch`, `oe sessions`, `oe report`, `oe rereads`,
`oe shrink`, `oe brief`, `oe savings`, `oe audit` and the retrieval commands all work on a
fresh clone with no setup.

**Hooks and the status line — opt-in, registered by `install.py`.** Three hook entries:

| event | script | timeout | what it does |
|---|---|---|---|
| `SessionStart` | `session_start.py` | 15s | create the session's report directory, record start metadata, start the per-session watcher, and hand the model a one-line retrieval hint |
| `UserPromptSubmit` | `user_prompt_submit.py` | 10s | put a compact budget line on screen, and into the model's context |
| `SessionEnd` | `session_end.py` | 180s | the full synchronous report rebuild, and refresh the agent-read prior |

A fourth hook ships but is **not registered unless you ask for it**. `PreToolUse`, matched on
`Agent`, hands a spawning subagent a context brief — see
[The spawn brief](docs/commands.md#the-spawn-brief-off-by-default). It is off by default
because it is the only hook here that runs on a tool-call path, and because it pays only in
some usage regimes. Set `brief.enabled` in `config.json` and re-run `install.py --yes` to
switch it on; set it back to false and re-run to remove it.

Every hook wraps its body in try/except and **fails open**: it always exits 0, so a fault in
this tool can never block a Claude Code session.

Without the hooks the meter still works. What they add is a report directory and start/end
metadata written at the right moments, a watcher started without you asking, and the budget
line. Every number comes from the transcripts either way.

## What a read cost, against what it could have cost

`oe shrink` re-prices every file read in your transcripts against what this machine's own
index could have printed instead, and sorts the reads onto rungs: whole-file reads of files
that have a symbol table, reads that already named a line range, reads of files the index
never saw. For the first rung it renders `oe slice <path>` for real and counts the tokens,
so the alternative price is measured on your files rather than taken from a ratio.

It never reports a saving. Which symbol a reader wanted is not recorded anywhere, so the
result is an interval whose low end is zero — `oe` cannot know that an outline would have
answered the question, and does not assume it. Reads it cannot classify are counted and
labelled, never guessed at, and the rung where the index would have printed *more* than the
read is shown as a loss on its own line rather than netted away.

See [Command reference](docs/commands.md#oe-shrink-session--all) for the rungs and the
contract, and [Retrieval](docs/commands.md#retrieval) for the commands it prices against.

## You never start oe

Three separate things share the name, and only one of them is a process you run:

| piece | who runs it | when |
|---|---|---|
| the hooks | **Claude Code**, from `settings.json` | session start, every prompt, session end |
| the `oe` CLI | **you**, in a terminal | whenever you want to look at something |
| the supervisor / watcher | optional background process | started by `oe watch`, `oe supervise --ensure`, the `SessionStart` hook, or the shell-rc autostart block |

The watcher is the only optional background piece. It exists so `report.html` keeps updating
while a session runs and after you close the pane. Nothing else depends on it: every `oe`
command computes its own answer from the transcripts.

## Documentation

| document | what is in it |
|---|---|
| [Install](docs/install.md) | Requirements, `--check`, backing up your settings file, the dry run, local vs user scope, exactly what gets written, updating, uninstalling, pinning a version, shells and platforms, and the `oe: command not found` runbook. |
| [Command reference](docs/commands.md) | Every command and what it is for. Each entry shows how to invoke it, not what it prints — see [About the examples](docs/commands.md#about-the-examples) for why. |
| [Privacy](docs/privacy.md) | What is redacted, where, and what is not. Read it before a screenshot goes into a ticket. |
| [Configuration](docs/configuration.md) | Every `config.json` key and every environment variable, and why nothing here is tied to a machine or a person. |
| [Limits, troubleshooting and layout](docs/operations.md) | The known limits stated plainly, the troubleshooting runbook, what the tool writes and where, and how the repository and CI work. |

## Licence and contributing

MIT — see [LICENSE](LICENSE). That licence covers this tool. Claude Code itself is
Anthropic's, and what this repository records about its hook contract and its pricing tables
is **observed behaviour**, read out of an installed build, not a grant of anything.

To change something, [CONTRIBUTING.md](CONTRIBUTING.md) has the two hard constraints, the
never-commit list and the commands to run before you push. [SECURITY.md](SECURITY.md) is
where anything sensitive goes.
