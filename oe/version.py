"""What version this is, and what commit it came from -- `oe version`.

The version lives in ONE place: the `VERSION` file at the install root. A
release is a tag named `v` + the contents of that file, and the release
workflow refuses to publish a tag that disagrees with it
(`.github/workflows/release.yml`). So the file is not a note ABOUT the
version, it IS the version.

Reading a file instead of hardcoding the string here is what makes that check
possible: a bump is a one-line diff a reviewer can see, and CI can compare a
tag against it with `cat`, without importing Python at all.

`oe.__version__` is the fallback, for the case where the package was copied
somewhere without the root file beside it. It is the same number; `VERSION` is
the authority and this module prefers it.

`describe()` is the line a bug report wants: `1.0.0 (a1b2c3d, dirty)` says
"release 1.0.0 plus uncommitted edits", which is a different bug from
"release 1.0.0". It degrades to the bare version in silence -- a tarball
install has no `.git`, and that is a supported way to run this tool, not a
fault worth a warning.

Nothing here runs at import except one small file read; the git calls happen
only when something asks for them.
"""

from __future__ import annotations

import os
import subprocess

from pathlib import Path
from typing import Optional, Tuple

from . import __version__ as _IN_CODE_VERSION

#: `oe/version.py` -> the install root is one level up. Deliberately NOT
#: `paths.INSTALL_ROOT`, which OE_INSTALL_ROOT can point elsewhere: the
#: question here is "which tree is this code FROM", and the answer to that is
#: always the directory the module was loaded out of. Resolved, so a symlinked
#: checkout reports its own VERSION and not the one beside the symlink.
INSTALL_ROOT = Path(__file__).resolve().parent.parent
VERSION_FILE = INSTALL_ROOT / "VERSION"


def _read_version() -> str:
    """The contents of VERSION, or the in-code mirror when it is not there."""
    try:
        text = VERSION_FILE.read_text(encoding="utf-8")
    except Exception:
        return _IN_CODE_VERSION
    # First non-empty line only: a stray trailing line cannot turn the version
    # into a two-line string that then gets printed into a table.
    for line in text.splitlines():
        line = line.strip()
        if line:
            return line
    return _IN_CODE_VERSION


#: Read once, at import. The file cannot change under a running process in any
#: way that matters, and every caller is a print statement.
VERSION: str = _read_version()


def _git(*args: str) -> Optional[str]:
    """Run one read-only git command in the install root; None on any failure.

    Every failure mode collapses to None on purpose -- git not installed, git
    installed but not on PATH for this process, a repository too broken to
    answer, a network filesystem that hangs. None of those is worth a
    traceback from a command whose whole job is to print one line.
    """
    try:
        completed = subprocess.run(
            ("git", "-C", str(INSTALL_ROOT)) + args,
            capture_output=True, timeout=5,
            # The environment is inherited, not replaced: git reads HOME to
            # find ~/.gitconfig, and a checkout owned by another uid needs the
            # safe.directory entry that lives there. GIT_OPTIONAL_LOCKS=0 is
            # the one addition -- `git status` refreshes and rewrites the
            # index by default, and this is a read; printing a version must
            # not touch the user's repository.
            env=dict(os.environ, GIT_OPTIONAL_LOCKS="0"),
        )
    except Exception:
        return None
    if completed.returncode != 0:
        return None
    return completed.stdout.decode("utf-8", "replace").strip()


def revision() -> Optional[Tuple[str, bool]]:
    """`(short commit, dirty)` for a git checkout of THIS tree, else None.

    The toplevel comparison is not paranoia. The convention in the README puts
    this tree at `~/.claude/overwatch-enforcer`, and plenty of people keep
    `~/.claude` in a repository of their own. Run inside a directory that is
    not itself a checkout, `git rev-parse HEAD` cheerfully answers with the
    PARENT repository's commit -- a wrong answer that looks exactly like a
    right one, printed into a bug report about this tool.
    """
    top = _git("rev-parse", "--show-toplevel")
    if not top:
        return None
    try:
        if Path(top).resolve() != INSTALL_ROOT:
            return None
    except Exception:
        return None
    short = _git("rev-parse", "--short=7", "HEAD")
    if not short:
        return None                     # a checkout with no commit in it yet
    return short, bool(_git("status", "--porcelain"))


def describe() -> str:
    """`1.0.0`, or `1.0.0 (a1b2c3d, dirty)` when this is a checkout."""
    found = revision()
    if not found:
        return VERSION
    commit, dirty = found
    return f"{VERSION} ({commit}, dirty)" if dirty else f"{VERSION} ({commit})"
