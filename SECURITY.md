# Security

Overwatch Enforcer registers three hooks that Claude Code executes — at session
start, on each prompt, and at session end. None of them runs on a tool call.
`install.py` is the only component permitted to write Claude Code's
`settings.json`, and the redaction layer is the only thing keeping a shared
report from carrying a real address. A bug in any of those three is a security
bug, not a defect report.

**Please do not open a public issue for one.** Use GitHub's private
vulnerability reporting: the **Security** tab, then **Report a vulnerability**.

Particularly wanted:

- personal data that survives `oe audit`, `oe package`, or a rebuilt report
- any way the contents of a transcript can influence what a hook executes
- `install.py` writing outside the settings file it named, or an `--uninstall`
  that does not restore that file byte for byte
- a path that escapes `reports_root()` or `state_dir()`

This is a single-maintainer project with no service behind it, no bounty, and
no SLA. Expect a first reply within a couple of weeks.

Redact yourself before you send anything. `oe` redacts automatically whenever
stdout is not a terminal, so pipe it:

```sh
oe doctor | cat > doctor.txt
```

A screenshot of a terminal is **not** redacted, because stdout was a terminal.
