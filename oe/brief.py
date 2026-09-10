"""The context brief handed to a subagent at spawn.

WHY THIS EXISTS
---------------
A subagent starts with an empty window and discovers the codebase by reading.
Measured on this machine, agent windows carry the overwhelming majority of read
cost, and `oe` has never been able to reach them: it registers `SessionStart`
and `UserPromptSubmit`, both main-loop, so by the time an agent exists there is
no boundary left to act on. The spawn call itself is that boundary.

WHAT IT PRODUCES
----------------
Not file bodies. A ranked set of SYMBOL TABLES -- the same thing `oe slice
<path>` prints with no target -- for the nodes the task looks like it is about,
plus one directional hop along the import graph from the best of them. That is
the "node, then a directional subtree" shape `oe deps` already uses, applied to
a prompt instead of a path.

WHAT IT IS NOT
--------------
It is not a substitute for reading. An outline names what is in a file and
where; it carries no bodies, and the brief says so in its own text, because an
agent that treats a symbol table as the content will read the file anyway and
the window pays twice.

THE ECONOMICS, AND WHY THERE IS A BUDGET
----------------------------------------
Anything injected at spawn is resident for the agent's whole life and is
re-billed on every one of its requests. A read that happens late is carried by
far fewer. So a brief is only worth its place if it is SMALL and OFTEN RIGHT,
and the honest control is a token budget rather than a file count: a budget
bounds the downside directly, whereas `k` bounds only the number of guesses.
Retrieval accuracy is the binding constraint here and it is not close to
perfect, so the budget is the safety rail, not the ranking.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Sequence, Tuple

#: Default ceiling on the injected text. Deliberately small. This is not a
#: measured optimum -- it is a bound chosen so that a brief which is entirely
#: wrong still costs less than one avoided whole-file read.
DEFAULT_BUDGET_TOKENS = 1500

#: How many candidates to ask the index for before the budget trims them.
DEFAULT_K = 24

#: Words that carry no retrieval signal in a task prompt. Kept short on purpose:
#: an aggressive stop list throws away domain terms, and the index's own ranking
#: is better at discounting common words than a hand-written list is.
_STOP = frozenset("""
a an and are as at be been but by can could did do does for from had has have
how if in into is it its may might must of on or should so than that the their
then there these they this those to was were what when where which who why will
with would you your please make sure need want use using run read file files
code task agent think about look check find test tests write output return
""".split())

_WORD = re.compile(r"[A-Za-z_][A-Za-z0-9_]{2,}")
#: A path-shaped token in the prompt is a much stronger signal than a word.
_PATHISH = re.compile(r"[\w~.\-/]*/[\w.\-/]+\.\w{1,6}")


def _retrieval():
    from oe import retrieval
    return retrieval


def _store():
    from oe import store
    return store


def terms(prompt: str, limit: int = 12) -> List[str]:
    """The query this prompt becomes. Frequency-ranked, stopped, deduped."""
    import collections
    head = str(prompt or "")[:4000]
    counts: "collections.Counter[str]" = collections.Counter()
    for word in _WORD.findall(head.lower()):
        if word in _STOP or word.isdigit():
            continue
        counts[word] += 1
    return [word for word, _n in counts.most_common(limit)]


def named_paths(prompt: str) -> List[str]:
    """Paths written out in the prompt. These outrank anything retrieved.

    Measured: only a small minority of an agent's reads are of files its prompt
    names -- so this is a high-precision, low-recall signal. It is used to seed
    the brief, never as the whole of it.
    """
    store = _store()
    out: List[str] = []
    seen = set()
    for hit in _PATHISH.findall(str(prompt or "")[:4000]):
        key = store.norm_path(hit)
        if key in seen:
            continue
        seen.add(key)
        out.append(key)
    return out


def _outline_of(path: str) -> Optional[Tuple[str, int]]:
    """(rendered outline, tokens) for one path, or None if it has no symbols."""
    ret = _retrieval()
    try:
        res = ret.slice_(path)
    except Exception:
        return None
    if res.get("mode") != "outline" or not res.get("outline"):
        return None
    text = str(ret.render_slice(res))
    return text, int(ret.est_tokens(text))


def candidates(prompt: str, *, k: int = DEFAULT_K, expand: int = 4) -> List[str]:
    """Paths worth briefing on, best first.

    Three sources, in descending confidence: paths the prompt names, paths the
    index ranks for the prompt's terms, and one directional hop out of the best
    ranked path. The hop is what makes this a graph query rather than a search:
    a task about one module is usually a task about what that module imports.
    """
    store = _store()
    ordered: List[str] = []
    seen = set()

    def add(path: str) -> None:
        key = store.norm_path(path)
        if key and key not in seen:
            seen.add(key)
            ordered.append(key)

    for path in named_paths(prompt):
        add(path)

    query = " ".join(terms(prompt))
    if query:
        try:
            for hit in store.search(query, k=k):
                add(str(hit.get("path") or ""))
        except Exception:
            pass

    # One hop OUT of the strongest node. Depth 1 only: depth 2 fans out fast
    # enough to spend the whole budget on files nobody asked about.
    if ordered and expand:
        try:
            sub = store.subtree(ordered[0], depth=1, k=expand * 2, direction="out")
            for row in (sub.get("files") or [])[:expand]:
                add(row.get("path") if isinstance(row, dict) else str(row))
        except Exception:
            pass
    return ordered


def build(prompt: str, *, budget_tokens: int = DEFAULT_BUDGET_TOKENS,
          k: int = DEFAULT_K) -> Dict[str, Any]:
    """The brief, bounded by `budget_tokens`. Never raises."""
    picked: List[Dict[str, Any]] = []
    spent = 0
    skipped_budget = 0
    try:
        paths = candidates(prompt, k=k)
    except Exception:
        paths = []
    for path in paths:
        got = _outline_of(path)
        if got is None:
            continue
        text, tokens = got
        if spent + tokens > budget_tokens:
            skipped_budget += 1
            # Keep scanning: a later, smaller outline may still fit, and
            # stopping at the first overflow would bias the brief toward
            # whatever happened to be ranked first.
            continue
        picked.append({"path": path, "tokens": tokens, "text": text})
        spent += tokens
    return {"files": picked, "tokens": spent, "budget_tokens": budget_tokens,
            "considered": len(paths), "skipped_over_budget": skipped_budget}


#: The framing sentence. It has one job: stop an agent treating a symbol table
#: as the file. Without it the brief is worse than nothing, because the window
#: pays for the outline AND for the read that follows it.
PREAMBLE = (
    "Context brief from `oe` -- SYMBOL TABLES ONLY, no file bodies. These name "
    "what is in each file and the lines it is on, so you can go straight to a "
    "span instead of reading the whole file: `oe slice <path> <symbol>`. They "
    "are a map, not the content. If you need a body, read it. If the file you "
    "want is not here, this brief simply did not predict it -- it is retrieval "
    "over an index, and it is often wrong."
)


def render(brief: Dict[str, Any]) -> str:
    """The text appended to a spawn prompt, or "" when there is nothing worth saying."""
    files = brief.get("files") or []
    if not files:
        return ""
    parts = ["\n\n---\n" + PREAMBLE + "\n"]
    for row in files:
        parts.append(row["text"].rstrip() + "\n")
    parts.append(
        "\n(%d file(s), ~%d tokens, budget %d. This text is resident for this "
        "agent's whole life and re-billed on every request it makes.)\n"
        % (len(files), int(brief.get("tokens") or 0), int(brief.get("budget_tokens") or 0)))
    return "".join(parts)
