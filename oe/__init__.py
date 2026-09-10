"""Overwatch Enforcer: token/cost accounting for Claude Code sessions.

Stdlib only, no network. The package is imported both by long-lived processes
(the watcher) and by latency-critical ones (the statusline, hooks), so nothing
expensive may run at import time -- keep this file free of side effects.
"""

__version__ = "1.0.0"

# Bump when SessionLedger.to_dict() changes shape, so report.py / dashboard.py
# can refuse to render a payload they do not understand.
SCHEMA_VERSION = 1

__all__ = ["__version__", "SCHEMA_VERSION"]
