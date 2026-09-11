# Install

*Part of the [Overwatch Enforcer](../README.md) documentation. [← README](../README.md)*

```sh
git clone https://github.com/ThiagoDallacqua/overwatch_enforcer
cd overwatch_enforcer

python3 install.py --check     # the dependency checklist. Writes nothing, ever.
python3 install.py             # checklist, prompts, then a DRY RUN diff. Still writes nothing.
python3 install.py --yes       # the same, then writes.

OE=$PWD                        # every command below uses $OE
```

The repository is named `overwatch_enforcer`, with an **underscore**, so that is the
directory `git clone` creates and the one `cd` has to name. Back the settings file up before
the `--yes` run ([Back up your settings file](#back-up-your-settings-file)). If the install
succeeds but a fresh terminal answers `oe: command not found`, nothing is broken and nothing
needs reinstalling — that is PATH, and it has its own section
([If oe is not found](#if-oe-is-not-found)).

**Where you clone it is your choice.** Every entry point derives the install root from its
own `__file__` — `oe/paths.py`, `install.py`, each hook, `bin/oe` — so a clone at
`~/src/overwatch_enforcer`, at `~/.claude/overwatch-enforcer`, or anywhere else behaves
identically. (`OE_INSTALL_ROOT` overrides it, for a hook script copied out of the tree.) Two
things are worth weighing:

* **Keep it somewhere permanent.** A hook command is an absolute path into this directory.
  Deleting or moving the checkout while the hooks are wired at user scope gives every session
  on the machine a failing hook until you re-run the installer. Moving it is supported and
  repairable — see [Updating and moving the checkout](#updating-and-moving-the-checkout).
* **Inside a project checkout is fine**, but read
  [Choosing a settings scope](#choosing-a-settings-scope) first. If the clone lives inside a
  repo you work in, `--scope local` keeps the two travelling together without committing
  anything.

## Requirements

| | |
|---|---|
| Interpreter | Python **3.10 or newer**. The checklist enforces it. |
| Packages | None. Standard library only — no `requirements.txt`, no virtualenv, no lockfile. |
| SQLite | `>= 3.9.0` with **FTS5**. The checklist also probes RTREE and JSON1 as headroom checks; the shipped schema uses neither. |
| Network | None. No command opens a socket. |
| Build step | None. Nothing is compiled or bundled at install time. |
| Git | To clone and to `git pull`. Nothing in the tool shells out to git, and a tarball install needs none. |
| Claude Code | Needed for the hooks and for `oe reprice`. `--allow-missing-claude` downgrades its absence to a warning. |
| Disk | `>= 64 MB` free. The context index is the only thing that grows; `oe find --stats` reports its size. |
| Platform | linux or darwin. See [Shells and platforms](#shells-and-platforms). |

## Check the machine first

```sh
python3 $OE/install.py --check          # or, once oe is reachable:
$OE/bin/oe doctor --install
```

It prints the **dependency checklist**: six groups (Runtime, Database, Claude Code, Package,
Filesystem, Interpreter), one row each, with the value found beside the value required and a
one-line remedy on any failure. Two severities: **FAIL** stops the run (exit 1, nothing
written) and **warn** is informational.

"Creates nothing" is literal — `--check` sets `sys.dont_write_bytecode` and passes `-B` to
the one subprocess it spawns, so a fresh clone is byte-for-byte identical afterwards, not
even a `__pycache__`. The same is true of a plain dry run. CI asserts it.

The tail of a run, shown for shape rather than as a transcript of yours — the paths and the
count depend on the machine (see [About the examples](commands.md#about-the-examples)):

```
$ python3 install.py --check | tail -n 8
  interpreter to bake in: /usr/bin/python3
  resolved from the interpreter running install.py


  PATH
    ok: `oe` already resolves to ~/overwatch_enforcer/bin/oe

  --check: the checklist only. Nothing was written.
```

`--no-binary-probe` skips the streaming read of the Claude Code executable — which is how
the `CLAUDE CODE` group confirms each hook event name is really in this build — and drops
the check count accordingly.

One row in that group is about the settings file rather than the machine, and it is the row
that matters after a `git pull` or a move:

```
  [ok]    hooks wired            3/3 hook entries -> this checkout + statusLine                   need: 3, or none
```

It reports **which checkout the settings file's entries actually run out of**. `not wired
(optional)` is an OK row, because zero configuration is a supported state. It warns, with
the offending root named, when entries point somewhere else — a previous location whose tree
is gone, or a second live copy — and when this checkout is wired but short an event, which
is what a release that adds a hook event produces. It is never a hard failure.

## Back up your settings file

`install.py` backs the file up itself, and you should still take a copy of your own. The
installer's copy protects you from a failed write; your copy protects you from the installer
being wrong. Neither makes the other unnecessary.

**What the installer does on its own, with no flag.** Before the first byte is written it
copies the target to `<settings>.bak-N` — `N` the first number not already taken, so an
existing `.bak-1` is never overwritten — then reads the copy back and compares it byte for
byte, and refuses to write at all if it does not match. After writing it re-reads what
landed and checks that every top-level key that is not ours is still there, unchanged and in
the original order; if that fails it restores the `.bak-N` and exits non-zero. If the write
fails before touching anything, the unused `.bak-N` is deleted rather than left as litter.

A separate, write-once `state/settings-baseline.<id>.json` records the file as it was
**before the first install**. That is what makes `--uninstall` byte-identical rather than
merely equivalent. `--no-backup` skips the `.bak-N` only; the baseline is still recorded.

**The copy you take yourself.** Its whole value is that it does not depend on any of the
above being correct. Which file it is depends on the scope you are about to choose — get
this right, because backing up the user file and installing into the project one protects
nothing:

```sh
# --scope user  -- CLAUDE_CONFIG_DIR wins over ~/.claude whenever it is set,
#                  and Claude Code honours it, so this is not always ~/.claude
SETTINGS="${CLAUDE_CONFIG_DIR:-$HOME/.claude}/settings.json"

# --scope project   SETTINGS="$PWD/.claude/settings.json"
# --scope local     SETTINGS="$PWD/.claude/settings.local.json"
# --settings PATH   SETTINGS="that path"

cp -p "$SETTINGS" ~/settings.json.pre-oe        # the backup
```

To put it back — a new shell will not have `$SETTINGS` set, so the restore repeats the line
that defines it:

```sh
SETTINGS="${CLAUDE_CONFIG_DIR:-$HOME/.claude}/settings.json"   # the same one as above
cp -p ~/settings.json.pre-oe "$SETTINGS"        # the restore
```

Then start a new Claude Code session; a running one has already read the file.

* **If `$SETTINGS` does not exist yet there is nothing to copy**, and `cp` says so. A correct
  uninstall of an install that *created* the file leaves no file behind either.
* **Keep the copy out of the repository** for `project` and `local` scope. A
  `.claude/settings.json.pre-oe` inside a checkout is one `git add -A` from being committed.
* **Do not guess which file it is — have the installer tell you.** A plain
  `python3 install.py` writes nothing and prints `SETTINGS SCOPES DETECTED` with the full
  path of every candidate, then a `COMBINATION` block naming the one it would use.

## The dry run

```sh
python3 $OE/install.py          # checklist, prompts, then a DRY RUN diff. Writes nothing.
python3 $OE/install.py --yes    # the same, then writes.
```

`--yes` is the **authorisation to write**. It does not skip the prompts; the two are
orthogonal. Both prompts are prefilled and both have a flag equivalent:

| prompt | prefilled with | flag |
|---|---|---|
| install directory | the directory `install.py` is in | `--dir PATH` |
| settings scope | the recommended scope, with the reason printed | `--scope {user,project,local}` or `--settings PATH` |

`--dir` names the directory this package **already lives in**; the installer wires up a
checkout, it does not copy one. Pointing it at an empty directory is refused.

With no terminal on stdin (piped, closed, CI, a hook) every prompt silently takes its default
and says so. It cannot hang and it cannot consume somebody else's piped data:

```sh
python3 $OE/install.py --yes --non-interactive --dir "$OE" --scope local
```

The change list and diff, from the fixture install:

```
$ python3 install.py | sed -n '/^  changes:/,$p'
  changes:
    - create key: hooks
    - create event: hooks.SessionStart
    - add group: hooks.SessionStart[matcher omitted]
    - add hook: SessionStart -> hooks/session_start.py (timeout 15s)
    - create event: hooks.UserPromptSubmit
    - add group: hooks.UserPromptSubmit[matcher omitted]
    - add hook: UserPromptSubmit -> hooks/user_prompt_submit.py (timeout 10s)
    - create event: hooks.SessionEnd
    - add group: hooks.SessionEnd[matcher omitted]
    - add hook: SessionEnd -> hooks/session_end.py (timeout 180s)
    - add statusLine: /usr/bin/python3 ~/overwatch_enforcer/oe/statusline.py

--- a/settings.json
+++ b/settings.json
@@ -0,0 +1,43 @@
+{
+  "hooks": {
+    "SessionStart": [
+      {
+        "hooks": [
+          {
+            "type": "command",
+            "command": "/usr/bin/python3 ~/overwatch_enforcer/hooks/session_start.py",
+            "timeout": 15
+          }
+        ]
+      }
+    ],
+    "UserPromptSubmit": [
+      {
+        "hooks": [
+          {
+            "type": "command",
+            "command": "/usr/bin/python3 ~/overwatch_enforcer/hooks/user_prompt_submit.py",
+            "timeout": 10
+          }
+        ]
+      }
+    ],
+    "SessionEnd": [
+      {
+        "hooks": [
+          {
+            "type": "command",
+            "command": "/usr/bin/python3 ~/overwatch_enforcer/hooks/session_end.py",
+            "timeout": 180
+          }
+        ]
+      }
+    ]
+  },
+  "statusLine": {
+    "type": "command",
+    "command": "/usr/bin/python3 ~/overwatch_enforcer/oe/statusline.py",
+    "refreshInterval": 5,
+    "padding": 0
+  }
+}


  DIAGNOSE ONLY -- nothing was written.
```

`--yes` prints the identical block and then explains why it will not act:

```
  --yes was refused.
    This build does not repair. The repair path can delete a hook
    that is WORKING -- it resolves $CLAUDE_PROJECT_DIR and relative
    paths against the directory you are standing in, and it reads
    `uv run x.py` and `npx tsx x.ts` as a missing script. Removing
    a live PreToolUse entry stops every tool call in every session
    on this machine, which is worse than the fault above.
```

Apply the listed changes by hand, take a copy of the file first, then start a new Claude Code
session. The repair path is still held back — see [Known limits](operations.md#known-limits).

## Choosing a settings scope

Install directory and settings scope are **independent axes**, and the installer validates
the combination separately from either one.

| scope | file | reach | committed to git? |
|---|---|---|---|
| `user` | `~/.claude/settings.json` | every project on this machine | no |
| `project` | `<project>/.claude/settings.json` | that project | **usually yes** |
| `local` | `<project>/.claude/settings.local.json` | that project, this machine only | no (gitignored) |

`managedSettings` and `policySettings` belong to an administrator. They are deliberately
absent from the installer's scope table and it will never write them.

| situation | scope | interpreter |
|---|---|---|
| Personal machine, package outside any repo | `user` | absolute (default) |
| Personal machine, package vendored inside one repo you work in | `local` | absolute (default) |
| **Shared repo, you want teammates to get it** | `project` | `--interpreter python3` — read the trap below |
| Shared repo, you want it for yourself only | `local` | absolute (default) |
| CI | `--settings <path>` plus `--yes --non-interactive` | `python3` |

The scope table reports, per candidate file, its size, whether it is valid JSON (with the
line number if not), how many hook events it already has, whether it has a `statusLine`, and
how many entries are already ours. "Ours" is decided by the **shape** of the command —
`<anything>/hooks/<one of ours>.py`, `<anything>/oe/statusline.py` — not by the directory
being called anything in particular, so a clone named `overwatch_enforcer`, a legacy install
and a directory you renamed yourself are all counted. That matters when migrating from an old
location: the number tells you how many stale entries there are to sweep.

**The committed-hooks trap.** Hooks carry a command line into the install directory. Put
them in `<project>/.claude/settings.json`, commit it, and a teammate who clones the repo gets
hooks pointing at a directory that does not exist on their machine. Choosing `project` prints
a boxed warning and, on a terminal, **requires a typed `yes`**. The one way to make a
committed install work is to commit the package inside the repo **and** pass
`--interpreter python3`, so the command carries no machine-specific path either. For a
committed scope the interpreter default flips to `python3` automatically and says so.

Otherwise the default interpreter is the absolute path of the one running the installer, which
is unambiguous on a box with several version managers on it. Whatever is chosen is **executed
before it is written** — the installer runs it, reads back its version, and asks its own
`sqlite3` whether FTS5 works, so an interpreter that would fail at hook time fails the
checklist instead.

## What it writes

Exactly two top-level keys in one settings file: `hooks` and `statusLine`.
`--only {all,hooks,statusline}` narrows that. Properties that are asserted, not hoped for:

* **Your own hooks survive.** Ours go into their own unmatched group; yours keep their
  matchers. The top-level key list and order are compared before and after the write.
* **A `statusLine` belonging to something else is never clobbered.** `--force-statusline`
  replaces it and stashes the old one; `--uninstall` puts it back.
* Re-running `--yes` when everything is current is a clean no-op: no backup, no byte changes.
* A **partial** install — some events present, some hand-deleted — is detected, named and
  repaired by the same merge.
* A write that fails verification is rolled back from the `.bak-N` copy automatically.

It also does two things **outside** the settings file, both reversible and both announced in
the dry run.

**`oe` on PATH.** The install symlinks `oe` into the first writable one of `$XDG_BIN_HOME`,
`~/.local/bin`, `~/bin`, preferring one already on your PATH.

If none of those is on PATH the link is still made and the rc line for **your** shell is
printed; if none is writable, only the export line is. The install is complete either way.
An `oe` that belongs to **something else** is never overwritten (use `--bin-name`), while a
**dangling** `oe` link of our own shape — what a re-clone or a `mv` produces — is re-pointed
at this checkout. A regular file named `oe` is never touched in either direction. `--no-link`
opts out; `--link-dir DIR` picks the directory yourself.

**`config.json`, if you do not have one.** The repository tracks `config.example.json`, not
`config.json`: the live file is machine-local (it holds *your* `reports_root`). On the first
`--yes` the installer copies the example into place. **Running with no `config.json` at all
is fully supported** — `load_config()` deep-merges over `DEFAULT_CONFIG`, so the code defaults
apply and every command works. The copy exists to give you a file with every key named in it.

A tree that arrived *with* a config (an `oe package` tarball, or a directory somebody copied)
carries somebody else's `reports_root`. If that directory does not exist on this machine the
install resets it to the portable default beside Claude Code's own config. A `reports_root`
that does exist is a deliberate local choice and is kept untouched.

Nothing else on disk is touched. In particular **the installer never edits a shell rc file** —
that is `oe autostart`'s job and it stays opt-in. The reports tree, the state directory and
the context index are created lazily by the commands that need them.

**One thing to check before you hand the tree to somebody.** `state/` is runtime data, not
code: the account map (a real address), the session map that undoes every pseudonym in the
reports, a cost cache of absolute paths and session titles, and a context index built from
whatever source tree this machine works in. `.gitignore` is an allowlist and keeps it out of
a git clone structurally, but a directory copy or a zip carries all of it. The dependency
checklist notices, and its `carried state` row names the size, whose it is, and the `rm -rf`
that clears it.

## Updating and moving the checkout

```sh
cd $OE && git pull && python3 install.py --yes && oe supervise --ensure
```

**`install.py --yes` IS the updater.** There is no `oe update`, because the installer already
is one: it is idempotent, it repairs a partial install, it re-points every hook command and
the `statusLine` if the checkout moved, it sweeps the entries the old path left behind, and
it re-points the `oe` symlink. On most pulls it will say there was
nothing to do, and that is the answer you wanted.

`oe supervise --ensure` is there because the supervisor is a long-lived process: it keeps
executing the code it started with, so a pull alone does not reach it. `--ensure` compares the
code on disk with the code the running supervisor started from and, when they differ, replaces
it. The one exception is a supervisor running inside `oe watch --inline`, which stops with that
view and is left alone. Nothing else needs restarting — the hooks are spawned fresh by Claude Code every time, and
the CLI is a script.

**Your data and your settings are not in the repository**, which is what makes `git pull`
safe. `state/` and `config.json` are untracked. The context index self-heals a schema bump on
its own. `oe reprice` tracks the *Claude Code* binary, not this repository, so a pull never
requires one — but note that it rewrites the tracked file `oe/pricing.py`, so the next
`git pull` will want that change stashed or committed.

**Moving or re-cloning is supported.** Re-run `python3 install.py --yes` from the new
location. The install banner tells you which case you are in, and it reads the state
directory rather than the directory's shape, so a fresh clone is never announced as an
upgrade:

```
  install directory  ~/overwatch_enforcer
                     a clean checkout -- first install
```

`existing install -- upgrade in place` requires a `state/`, which only an actual install
creates and which is never in a clone.

## Uninstall

```sh
python3 $OE/install.py --uninstall --yes
```

**The target comes from the install record, not from the directory you are standing in.**
`state/install-manifest.json` records every settings file an install touched, and the
uninstall reads it first. It cleans **every scope the record names**, one pass per file, and
prints them up front:

```
$ python3 install.py --uninstall
  UNINSTALL TARGETS
  ============================================================================
  chosen from what this install actually touched, not from the directory you are standing in
  user       ~/.claude/settings.json
             named in the install record
```

`--scope` or `--settings` override the record on purpose. If you force a scope that holds
none of our entries while another file does, the run removes nothing from either, names the
file that does hold them, leaves the PATH link in place so `oe` is still available to finish
the job, and **exits 2**.

It removes exactly our entries and, when the result is the document we first saw, restores
the **original bytes** from the baseline taken at install time. Before doing anything it
compares the manifest against the file on disk and tells you which of two situations you are
in:

```
  SINCE THE INSTALL
    settings.json is byte-for-byte what we wrote -- nobody has edited it since.
    so taking our entries back out lands on the pre-install file exactly, and restoring it is a provable undo, not a guess.
```

```
  SINCE THE INSTALL
  ! settings.json has been EDITED since we wrote it; its checksum no longer matches ours.
    removing only our own entries. Everything you added -- MCP servers, permissions, other tools' hooks -- is kept.
    --restore-backup would write the pre-install file back and DISCARD those edits. That is why it is not the default.
```

The second case is the normal one after a few months. Writing an old copy over such a file
would destroy every MCP server and permission you have added since, so the default never does
that. A missing or unreadable manifest is not an error either: every verdict becomes
`unknown`, the uninstall says so and claims nothing, and the surgical removal proceeds exactly
as it would on a machine that never had one.

The change list, from the fixture uninstall:

```
$ python3 install.py --uninstall --yes | sed -n '/^  removed:/,$p'
  removed:
    - remove 1 hook(s) from SessionStart
    - remove empty group from SessionStart
    - remove empty event: hooks.SessionStart
    - remove 1 hook(s) from UserPromptSubmit
    - remove empty group from UserPromptSubmit
    - remove empty event: hooks.UserPromptSubmit
    - remove 1 hook(s) from SessionEnd
    - remove empty group from SessionEnd
    - remove empty event: hooks.SessionEnd
    - remove now-empty key: hooks
    - remove statusLine

  PATH
    - remove PATH link ~/.local/bin/oe -> ~/overwatch_enforcer/bin/oe
```

**`--restore-backup` is the opt-in for the other choice**, and it lists the top-level keys it
is about to lose before it does anything:

```sh
python3 $OE/install.py --uninstall --restore-backup        # dry run
python3 $OE/install.py --uninstall --restore-backup --yes  # writes
```

It prefers the write-once baseline over any `.bak-N`, because on an upgraded install the
newest `.bak` already contains our hooks and restoring it would reinstate the entries you are
removing. It backs up the current file first, verifies the result is byte-identical to the
source, and only then consumes the baseline. It also works when `settings.json` has been
deleted outright.

**The PATH block comes out too.** If `--path-fix` wrote a block into a shell rc file, the
uninstall cuts it back out — delimited, so it takes our block and nothing else, through the
same numbered-backup and `<shell> -n` gates as every other rc edit. The autostart block is
separate: `oe autostart --remove`.

To remove the optional pieces individually:

```sh
$OE/bin/oe uninstall-statusline --yes    # just the statusLine key
$OE/bin/oe autostart --remove            # just the shell-rc block
$OE/bin/oe supervise --stop              # stop the background supervisor
```

Deleting the whole directory removes the tool. The reports tree and `state/` are separate and
survive; delete them too if you want nothing left.

Two edges worth knowing: a settings file the install **created** is left behind as an empty
`{}` rather than deleted, and if the manifest is gone **and** the run cannot reach any
settings file, no evidence exists on the machine to identify one — the run prints a loud
warning naming that, and still exits 0, because an idempotent second uninstall must not fail.

## Pinning a version

```sh
$ oe version
1.0.4

$ oe version --json
{
  "version": "1.0.4",
  "commit": null,
  "dirty": null
}
```

In a checkout with history it appends the short commit, and `dirty` when the working tree has
uncommitted edits — `1.0.4 (abc1234)` and `1.0.4 (abc1234, dirty)` are different bug reports.
Anywhere with no `.git`, including a tarball install, it degrades silently to the bare
version. The commit is only reported when the repository it comes from **is this tree**, so a
checkout sitting inside somebody else's repository never prints that repository's commit into
your bug report.

The version lives in one file, `VERSION`, at the install root.

**Why pinning is worth it here.** `main` moves, and a hook command written into your
`settings.json` points at whatever is in the checkout at the moment Claude Code spawns it — so
a `git pull` changes the behaviour of every session on the machine, without a restart and
without asking. A tag does not move.

```sh
# a tag, as a checkout: `oe --version` reports the commit, and you can move later
git clone --branch v1.0.4 https://github.com/ThiagoDallacqua/overwatch_enforcer
cd overwatch_enforcer && python3 install.py

# to move to a later tag rather than to the tip of main
cd $OE && git fetch --tags && git checkout v1.1.0 && python3 install.py --yes
```

`--branch` takes a tag as well as a branch and detaches HEAD at it, so `git status` will say
`HEAD detached at v1.0.4`. That is expected. **Do not add `--depth 1` unless the checkout is
disposable** — git implies `--single-branch` with it, so the clone holds only the history
behind that one tag, `git checkout main` and any other tag both fail in it, and the fix is to
re-clone.

The other route is the Release asset — the leak-scanned bundle `oe package` built, which needs
no git:

```sh
gh release download v1.0.4 --repo https://github.com/ThiagoDallacqua/overwatch_enforcer --pattern '*.tar.gz'
tar xzf overwatch-enforcer-1.0.4.tar.gz
cd overwatch-enforcer && python3 install.py
```

Note the two directory names: the clone is `overwatch_enforcer` (underscore, the repository's
name) and the tarball unpacks to `overwatch-enforcer` (hyphen, the bundle's internal root). A
tarball install has no git and therefore no update path: download the newer asset, unpack it
over the same directory, and re-run `install.py --yes`.

**Distribution is GitHub only** — a `git clone` at a tag, or a Release asset. There is
deliberately no npm package, no `npx`, no Homebrew formula and no `curl | sh` bootstrap: a
package manager is a dependency and a build step, which is the one thing this project does not
have, and `install.py`'s central property is that you see a dry-run diff before anything is
written, which a pipe into a shell inverts exactly.

## Shells and platforms

| | |
|---|---|
| Platforms | `linux`, `darwin` (the checklist rejects anything else) |
| Shells for the autostart and PATH blocks | zsh, bash — the emitted lines also parse under `sh` and `dash` |
| Shells for everything else | any; the CLI is a Python script |

`oe autostart` and `install.py --path-fix` write to the file the shell actually sources:

| `$SHELL` | file written | why that one |
|---|---|---|
| zsh | `$ZDOTDIR/.zshrc`, else `~/.zshrc` | `ZDOTDIR` relocates the whole zsh dotfile set |
| bash on Linux | `~/.bashrc`, else `~/.bash_profile` | interactive non-login bash reads `.bashrc` |
| bash on macOS | `~/.bash_profile`, else `~/.bashrc` | every Terminal window is a **login** shell, which reads `.bash_profile` and not `.bashrc` |
| no `$SHELL` at all | zsh on darwin, bash elsewhere | cron, launchd, a container |
| anything else | refused, out loud | the block would not parse in fish or csh |

**You do not have to pick from this table.** `install.py --path-doctor` prints which shell it
detected and which rc file that shell actually reads, and `--path-fix` edits that one.
Choosing by hand is where this goes wrong: a line written into a file the shell never sources
looks exactly like a line that did not work. `--rc <file>` overrides the choice, and naming a
copy is how you rehearse it.

Whichever route wrote the line, it takes effect in **new** shells. If the directory was
already on PATH and only the *file* is new, the shell may still say `command not found` from
the command hash it built at startup — `hash -r` in bash, `rehash` in zsh, and a new terminal
needs neither.

Every rc edit, in both directions, goes through four gates: a numbered backup that is read
back and compared byte for byte, `<shell> -n` on the candidate text (the shell chosen from
the rc file's *name*, so `--rc ~/.bashrc` is checked by bash even on a zsh machine), an
atomic mode-preserving `os.replace`, and idempotence. An rc resolving outside the current
`$HOME` is refused unless you name it with `--rc`.

### The optional autostart block

`oe autostart --install` adds one delimited, guarded line so the supervisor is up from the
first terminal of the day. `oe autostart --status` prints the exact line it would write:

```
$ oe autostart --status
rc          ~/.bashrc  (missing)
installed   no
line        if [ -z "${OE_NO_AUTOSTART-}" ] && [ -x ~/overwatch_enforcer/bin/oe ] && command -v python3 >/dev/null 2>&1; then ( ~/overwatch_enforcer/bin/oe supervise --ensure >/dev/null 2>&1 </dev/null & ) ; fi
binary      ~/overwatch_enforcer/bin/oe
escape      export OE_NO_AUTOSTART=1
supervisor  not running
```

It does not block the shell (three builtin tests and a subshell that immediately backgrounds
its child, on the order of a millisecond), it is silent, it never pollutes `$?`, it is safe
under `set -e` and `set -u`, the install path is shell-quoted so a directory with a space
still parses, and it disappears when the tool does — `-x .../bin/oe` covers a deleted install
directory and `command -v python3` a missing interpreter.

**What it costs beyond that** is a resident daemon: `supervise --ensure` leaves one
long-lived `python3` behind, with no idle timeout by design, so reports keep being written
between sessions. It costs what an idle Python process costs, a small fraction of one core,
and exactly one process no matter how many terminals open at once (a flock decides the race).
It lives until `oe supervise --stop`, SIGTERM or reboot. If that is not a trade you want on a
login shell, do not install the block. `export OE_NO_AUTOSTART=1` disables it without an edit.

### If oe is not found

This is the common one, it is not a failed install, and nothing needs reinstalling: the
install worked and the shell cannot find the name. Ask the installer which of five reasons it
is. It writes nothing, ever, and it is runnable by its full path — which is the situation you
are in when you need it:

```sh
python3 $OE/install.py --path-doctor
```

```
  PATH DIAGNOSIS
  ============================================================================
    command name       oe
    this checkout      ~/overwatch_enforcer
    the executable     ~/overwatch_enforcer/bin/oe   ok
    `oe` resolves to  ~/.local/bin/oe   (ours)
    our link           ~/.local/bin/oe
    its directory      ~/.local/bin   is on PATH
    login shell        zsh
    rc file            ~/.zshrc   (does not exist)

  `oe` is on PATH and it is this checkout. Nothing to fix.
```

It exits 0 only when `oe` is reachable **and** it is this checkout, so it also works as a gate
in a script. What the last lines say, and what to do:

| what it reports | what it means | what fixes it |
|---|---|---|
| `is on PATH and it is this checkout` | nothing to fix | — |
| `not on your PATH` | the link is missing, or its directory is not searched | `--path-fix --yes` |
| `Its link is in a directory the shell does not search` | the link exists, the directory is not on PATH | `--path-fix --yes` |
| `does not run: the link is dangling or not executable` | usually a moved or re-cloned checkout | `python3 $OE/install.py --yes` re-points it |
| `is missing or not executable, so no amount of PATH will help` | `bin/oe` itself is gone or lost its `+x` | re-clone, or `chmod +x $OE/bin/oe` |
| `the shell is not finding` … `that is the shell's command hash` | the directory is on PATH and the file is new | `hash -r` (bash) / `rehash` (zsh), or a new terminal |

**The fix.** Same diagnosis, then a delimited PATH block in the rc file your login shell
really reads. It is a dry run until `--yes`:

```sh
python3 $OE/install.py --path-fix          # shows the exact block and the file. Writes nothing.
python3 $OE/install.py --path-fix --yes    # writes it.
```

The block is idempotent twice over: delimited, so re-running cannot append a second copy, and
guarded by a `case`, so re-sourcing the file cannot put the directory on PATH twice. Then
**open a new terminal, or `source` the file** — an rc file changes nothing about the shell you
are already in.

It **refuses**, loudly and leaving the file untouched, in four cases: an `oe` on PATH that
belongs to something else (adding our directory in front would shadow it), a login shell the
block is not valid in (it prints the `fish_add_path` equivalent instead of writing broken
syntax), an rc file that does not exist (creating one is a bigger decision than it looks — a
new `~/.bash_profile` on macOS stops bash reading `~/.profile`), and a missing `bin/oe`.

**When `oe` resolves to something that is not ours**, `--path-doctor` says `(NOT ours)` and
`--path-fix` will not shadow it. Install under another name and use that name everywhere:

```sh
python3 $OE/install.py --yes --bin-name oemeter
```

`--bin-name` renames the **link**, never `bin/oe` itself.

**The manual fallback:**

```sh
export PATH="$OE/bin:$PATH"        # in ~/.zshrc, ~/.bashrc or ~/.bash_profile
```

**The escape hatch that always works.** Nothing about this tool requires it to be on PATH.
Run it by its full path from the clone and every command behaves identically:

```sh
$OE/bin/oe doctor
$OE/bin/oe status
```

### Verified on Linux, reasoned but untested on macOS

**Verified** on Linux (WSL2, x86_64, zsh, SQLite 3.46.1): every command in the
[command reference](commands.md), the three hooks fed real payloads, the dependency
checklist, the installer dry run, `--yes`, `--uninstall --yes` and `--path-doctor`, and a
clean `oe audit --all` over the artifacts produced.

**Not verified on macOS. No Mac was used at any point.** What is *reasoned*:

| area | what the code does | risk |
|---|---|---|
| rc selection | prefers `~/.bash_profile` for bash, honours `ZDOTDIR` for zsh | low — the branch is explicit |
| paths with spaces | the install path is `shlex`-quoted | low — exercised on Linux |
| checklist | `SUPPORTED_PLATFORMS = ("linux", "darwin")` | low |
| **process liveness and RSS** | reads `/proc/<pid>/{comm,cmdline,cwd,stat}` and `/proc/self/statm` | **this is the one that degrades.** macOS has no `/proc` |
| browser open | `oe open` uses the platform opener | untested |

The `/proc` degradation is designed for and is not a crash. `claude_processes()` runs a
capability probe first and returns `None` — deliberately different from `[]` — when the
machine will not answer. The caller falls back to **mtime-only liveness**, where a
merely-thinking session looks the same as a closed one, and says so. On macOS expect liveness
to be less precise and the supervisor's `rss_mb` to be absent or wrong. Nothing else in the
primary path reads `/proc`.
