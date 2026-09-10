# Contributing

Small project, one maintainer. Issues and pull requests are welcome. The rules
below are the ones you could not guess from the source.

## The two hard constraints

1. **Python standard library only.** No third-party package, ever, in the tool
   or in CI. Linux and macOS, bash and zsh, Python 3.10 or newer.
2. **Zero config by default.** `install.py` is the only file that may write
   Claude Code's `settings.json`, and only with `--yes`. Hooks and the status
   line stay opt-in; nothing about the tool may become mandatory.

## Never commit

- `state/` — the account map (a real address), the session map that undoes
  every pseudonym in every report, a cost cache full of absolute paths and
  session titles, and a context database built from your own source trees.
- `config.json` — machine-local, and rewritten at runtime by `oe guard mode`.
  A tracked copy would publish a local path and break `git pull` on a dirty
  tree. Copy `config.example.json` if you want to tune something.
- `reports/`, `__pycache__/`, `*.pyc`, `*.bak`, `*.tmp`, `*.log`, `*.tar.gz`.

`.gitignore` is an **allowlist**: everything is excluded, and the files that
ship are re-admitted by name. So a new file is invisible to git until you add
it there *and* to `ROOT_FILES` or `TREES` in `oe/package.py`. That is
deliberate — `oe package` compares the two lists and reports any difference,
because "what the bundle contains" and "what the clone contains" drifting
apart is exactly where a leak hides.

Note that `.gitignore` does nothing about a file that is **already** tracked.
CI asserts the tracked list separately for that reason.

## Before you push

```sh
python3 -m compileall -q -f oe hooks install.py extract_pricing.py
python3 install.py --check --allow-missing-claude
python3 .github/scripts/leak_gate.py
oe package --dir            # run this one locally; see below
```

`oe package` is the real gate, and it has two tiers.

The **shape** tier looks for strings *shaped* like personal data — home paths,
addresses, uuids, branch names, issue keys. It is machine-independent, so CI
runs it (`.github/scripts/leak_gate.py`).

The **identity** tier matches the actual address, username, hostname and
account ids of the machine running it. That only has authority on *your*
machine. On a hosted runner `$USER` is `runner`, a word that appears in
`oe/redact.py`'s own generic-username list and in the README, so it would fail
every build for no reason at all. Run `oe package` yourself; CI cannot do it
for you.

Neither tier can see an employer name, a product name or a source-file
basename. Nothing about those is shaped like anything. Read your diff.

If the shape tier flags something you believe is safe, add the exact string to
`PLACEHOLDERS` in `oe/package.py` **with a one-line reason**. That table is a
reviewed list, not a mute button: an entry earns its place by being a value
that cannot identify anybody — an invented path, a regex character class, an
encoding name, a unit.

## Filing an issue

`oe` redacts automatically whenever stdout is not a terminal, so pipe it:

```sh
oe doctor | cat > doctor.txt
```

A screenshot of a terminal is **not** redacted. For anything that looks like a
vulnerability, read [SECURITY.md](SECURITY.md) instead.
