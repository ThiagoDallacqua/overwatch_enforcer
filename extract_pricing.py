#!/usr/bin/env python3
"""Re-derive oe/pricing.py's tables from the installed Claude Code binary.

Claude Code bakes its model catalog into the bundle as a JS object literal:

    pricing_tiers:{tier_2_10:{input:2,output:10,cache_write_5m:2.5,...}, ...},
    models:[{id:"claude-opus-5",...,context:{window:1e6,native_1m:!0},
             max_output_tokens:{...},pricing:"tier_5_25",...}, ...]

It is JS, not JSON (bare keys, `!0`, `1e6`), so it is scanned with a bracket
walker plus field regexes rather than json.loads. Run this after every Claude
Code upgrade -- a new model that is missing from the table is counted as
unpriced, which is loud but wrong, and a changed tier is silently wrong, which
is worse.

    python3 extract_pricing.py              # print the regenerated block + a diff
    python3 extract_pricing.py --write      # rewrite the block in oe/pricing.py
    python3 extract_pricing.py --binary P   # use a specific binary
    python3 extract_pricing.py --json       # emit the catalog as JSON
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

def _versions_dirs() -> List[Path]:
    """Every place a Claude Code install keeps its versioned binaries, in the
    order they are worth trying. Derived, not hardcoded: the native installer
    uses ~/.local/share/claude on Linux, Application Support on macOS, and
    XDG_DATA_HOME relocates the first of those.
    """
    home = Path.home()
    xdg = os.environ.get("XDG_DATA_HOME")
    out = []
    if xdg:
        out.append(Path(xdg).expanduser() / "claude" / "versions")
    out.append(home / ".local" / "share" / "claude" / "versions")
    out.append(home / "Library" / "Application Support" / "claude" / "versions")
    out.append(home / ".claude" / "versions")
    seen, unique = set(), []
    for path in out:
        if str(path) not in seen:
            seen.add(str(path))
            unique.append(path)
    return unique


def versions_dir() -> Path:
    """The first versions directory that exists; the platform default if none do."""
    for candidate in _versions_dirs():
        try:
            if candidate.is_dir():
                return candidate
        except Exception:
            continue
    return _versions_dirs()[0]


VERSIONS_DIR = versions_dir()
# oe/pricing.py sits beside this script, in the same checkout.
PRICING_PY = Path(__file__).resolve().parent / "oe" / "pricing.py"

BEGIN = "# --- BEGIN GENERATED TABLE (extract_pricing.py --write rewrites this block) ---"
END = "# --- END GENERATED TABLE ---"

_TIER_RE = re.compile(
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*:\s*\{\s*"
    r"input\s*:\s*(?P<input>[\d.eE+-]+)\s*,\s*"
    r"output\s*:\s*(?P<output>[\d.eE+-]+)\s*,\s*"
    r"cache_write_5m\s*:\s*(?P<cw5>[\d.eE+-]+)\s*,\s*"
    r"cache_write_1h\s*:\s*(?P<cw1>[\d.eE+-]+)\s*,\s*"
    r"cache_read\s*:\s*(?P<read>[\d.eE+-]+)\s*,\s*"
    r"web_search\s*:\s*(?P<search>[\d.eE+-]+)\s*\}")

_ID_RE = re.compile(r'\bid\s*:\s*"([^"]+)"')
_PRICING_RE = re.compile(r'\bpricing\s*:\s*"([^"]+)"')
_WINDOW_RE = re.compile(r"context\s*:\s*\{\s*window\s*:\s*([\d.eE+]+)")
_DISPLAY_RE = re.compile(r'display_name\s*:\s*"([^"]+)"')


def newest_binary() -> Optional[Path]:
    """Highest installed version, comparing numerically not lexically."""
    try:
        candidates = [p for p in VERSIONS_DIR.iterdir() if p.is_file()]
    except OSError:
        return None

    def key(path: Path) -> Tuple:
        parts = re.findall(r"\d+", path.name)
        return tuple(int(p) for p in parts) if parts else (0,)

    return max(candidates, key=key) if candidates else None


def _num(text: str) -> float:
    value = float(text)
    return value


def _split_objects(body: str) -> List[str]:
    """Top-level {...} members of a JS array body."""
    out: List[str] = []
    depth = 0
    start = 0
    in_string = False
    quote = ""
    escape = False
    for index, char in enumerate(body):
        if in_string:
            if escape:
                escape = False
            elif char == "\\":
                escape = True
            elif char == quote:
                in_string = False
            continue
        if char in ('"', "'"):
            in_string = True
            quote = char
            continue
        if char == "{":
            if depth == 0:
                start = index
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                out.append(body[start:index + 1])
    return out


def _array_body(text: str, open_index: int) -> str:
    depth = 0
    for index in range(open_index, len(text)):
        char = text[index]
        if char == "[":
            depth += 1
        elif char == "]":
            depth -= 1
            if depth == 0:
                return text[open_index + 1:index]
    return ""


def extract(binary: Path) -> Dict[str, Any]:
    """Pull tiers, models and the fast-mode override out of the bundle."""
    blob = binary.read_bytes().decode("utf-8", errors="replace")
    anchor = blob.find("pricing_tiers:{")
    if anchor < 0:
        raise SystemExit(f"no pricing_tiers literal in {binary} -- bundle layout changed")
    models_at = blob.find("models:[", anchor)
    if models_at < 0:
        raise SystemExit(f"no models catalog after pricing_tiers in {binary}")

    tiers: Dict[str, Dict[str, float]] = {}
    for match in _TIER_RE.finditer(blob, anchor, models_at):
        tiers[match.group("name")] = {
            "input": _num(match.group("input")),
            "output": _num(match.group("output")),
            "cache_write_5m": _num(match.group("cw5")),
            "cache_write_1h": _num(match.group("cw1")),
            "cache_read": _num(match.group("read")),
            "web_search": _num(match.group("search")),
        }

    models: List[Dict[str, Any]] = []
    for entry in _split_objects(_array_body(blob, models_at + len("models:"))):
        model_id = _ID_RE.search(entry)
        tier = _PRICING_RE.search(entry)
        if not model_id or not tier:
            continue
        window = _WINDOW_RE.search(entry)
        display = _DISPLAY_RE.search(entry)
        models.append({
            "id": model_id.group(1),
            "pricing": tier.group(1),
            "window": int(_num(window.group(1))) if window else None,
            "display_name": display.group(1) if display else model_id.group(1),
            "native_1m": "native_1m:!0" in entry,
        })

    fast_tiers = _fast_mode_branches(blob, tiers)
    return {
        "version": binary.name,
        "binary": str(binary),
        "tiers": tiers,
        "models": models,
        "fast_mode_tiers": fast_tiers,
        "fast_mode_models": sorted(fast_tiers),
        "fast_mode_tier": fast_tiers.get("claude-opus-5") or fast_tiers.get("claude-opus-4-8"),
        "geo_multipliers": _geo_multipliers(blob),
    }


def _baked_costs(blob: str, symbol: str) -> Optional[Tuple[float, float, float, float, float]]:
    """The five per-1M numbers of a baked ModelCosts literal, by symbol name."""
    match = re.search(
        re.escape(symbol) + r"=\{inputTokens:([\d.]+),outputTokens:([\d.]+),"
        r"promptCacheWriteTokens:([\d.]+),promptCacheWrite1hTokens:([\d.]+),"
        r"promptCacheReadTokens:([\d.]+)", blob)
    if not match:
        return None
    return tuple(float(match.group(i)) for i in range(1, 6))  # type: ignore[return-value]


def _tier_name_for(costs: Tuple[float, ...], tiers: Dict[str, Dict[str, float]]) -> str:
    """Match a baked cost object back to a catalog tier, or invent a stable name.

    `kx` -- the Opus 4.6/4.7 fast-mode object -- deliberately has NO entry in
    pricing_tiers, so a lookup-only implementation drops that branch entirely.
    """
    for name, values in tiers.items():
        have = (values["input"], values["output"], values["cache_write_5m"],
                values["cache_write_1h"], values["cache_read"])
        if have == costs:
            return name
    name = "fast_%s_%s" % (("%g" % costs[0]).replace(".", "_"),
                           ("%g" % costs[1]).replace(".", "_"))
    tiers[name] = {"input": costs[0], "output": costs[1], "cache_write_5m": costs[2],
                   "cache_write_1h": costs[3], "cache_read": costs[4], "web_search": 0.01}
    return name


def _fast_mode_branches(blob: str, tiers: Dict[str, Dict[str, float]]) -> Dict[str, str]:
    """model id -> tier name, for every `usage.speed === "fast"` branch.

    Read from the PER-REQUEST resolver (minified `o5t`, the function reached by
    `NO(model, usage) = Nke(o5t(model, usage), usage)`), never from the display
    helper `Oke`: Oke knows only the Opus 5 / 4.8 pair, so extracting from it
    silently drops the Opus 4.6 / 4.7 branch and under-charges those 6x.
    """
    out: Dict[str, str] = {}
    anchor = re.search(r'if\(t\.speed==="fast"\)\{(.*?)\}(?:let |var |if\()', blob, re.S)
    if anchor is None:
        anchor = re.search(r'\.speed==="fast"\)\{(.{0,600}?)\}\s*let ', blob, re.S)
    if anchor is None:
        return out
    body = anchor.group(1)
    for branch in re.finditer(r'if\(((?:[A-Za-z_$][\w$]*===\s*"[^"]+"\|\|?)*'
                              r'[A-Za-z_$][\w$]*===\s*"[^"]+")\)return ([A-Za-z_$][\w$]*)',
                              body):
        ids = re.findall(r'===\s*"([^"]+)"', branch.group(1))
        costs = _baked_costs(blob, branch.group(2))
        if not ids or costs is None:
            continue
        tier_name = _tier_name_for(costs, tiers)
        for model_id in ids:
            out[model_id] = tier_name
    return out


def _geo_multipliers(blob: str) -> Dict[str, float]:
    """`Tee(usage)` -- the factor applied to the token part of every request."""
    match = re.search(r'function ([A-Za-z_$][\w$]*)\(e\)\{return e\.inference_geo==="([^"]+)"\?'
                      r'([A-Za-z_$][\w$]*|[\d.]+):1\}', blob)
    if not match:
        return {}
    geo, symbol = match.group(2), match.group(3)
    try:
        value = float(symbol)
    except ValueError:
        found = re.search(r'(?:var |,)' + re.escape(symbol) + r'=([\d.]+)[,;]', blob)
        if not found:
            return {}
        value = float(found.group(1))
    return {geo: value}


def render_block(catalog: Dict[str, Any]) -> str:
    lines: List[str] = [BEGIN, f'PRICING_SOURCE_VERSION = "{catalog["version"]}"', "", ""]
    lines += [
        "@dataclass(frozen=True)",
        "class Tier:",
        '    """USD per 1M tokens, except web_search which is USD per request."""',
        "",
        "    input: float",
        "    output: float",
        "    cw_5m: float",
        "    cw_1h: float",
        "    cache_read: float",
        "    web_search: float",
        "",
        "",
        "TIERS: Dict[str, Tier] = {",
    ]
    for name in sorted(catalog["tiers"], key=lambda n: (catalog["tiers"][n]["input"], n)):
        values = catalog["tiers"][name]
        lines.append("    \"%s\": Tier(%s, %s, %s, %s, %s, %s)," % (
            name, float(values["input"]), float(values["output"]),
            float(values["cache_write_5m"]), float(values["cache_write_1h"]),
            float(values["cache_read"]), float(values["web_search"])))
    lines += ["}", "", "MODEL_TIERS: Dict[str, str] = {"]
    for model in catalog["models"]:
        lines.append('    "%s": "%s",' % (model["id"], model["pricing"]))
    lines += ["}", "", "CONTEXT_WINDOWS: Dict[str, int] = {"]
    for model in catalog["models"]:
        if model["window"]:
            lines.append('    "%s": %d,' % (model["id"], model["window"]))
    lines += ["}", "", "DISPLAY_NAMES: Dict[str, str] = {"]
    for model in catalog["models"]:
        lines.append('    "%s": "%s",' % (model["id"], model["display_name"]))
    fast = catalog.get("fast_mode_tiers") or {}
    lines += [
        "}",
        "",
        "# Every `usage.speed === \"fast\"` branch of the per-request price resolver",
        "# (minified `o5t`), NOT the display helper `Oke` -- Oke knows only the",
        "# Opus 5 / 4.8 pair and reading it drops the 4.6 / 4.7 branch entirely.",
        "FAST_MODE_TIERS: Dict[str, str] = {",
    ]
    for model_id in sorted(fast):
        lines.append('    "%s": "%s",' % (model_id, fast[model_id]))
    lines += [
        "}",
        "FAST_MODE_MODELS = tuple(FAST_MODE_TIERS)",
        'FAST_MODE_TIER = "%s"  # retained for callers that predate the map'
        % (catalog.get("fast_mode_tier") or "tier_10_50"),
        "",
        "# `Nke` multiplies the TOKEN part of the cost (not the per-request web-search",
        "# charge) by `Tee(usage)`.",
        "INFERENCE_GEO_MULTIPLIERS: Dict[str, float] = {",
    ]
    for geo in sorted(catalog.get("geo_multipliers") or {}):
        lines.append('    "%s": %s,' % (geo, catalog["geo_multipliers"][geo]))
    lines += ["}", END]
    return "\n".join(lines) + "\n"


def compare(catalog: Dict[str, Any]) -> List[str]:
    """Differences between the binary and the table currently in pricing.py."""
    sys.path.insert(0, str(PRICING_PY.parent.parent))
    try:
        from oe import pricing  # noqa: PLC0415  (deliberate late import)
    except Exception as error:  # pragma: no cover - only if the package is broken
        return [f"could not import oe.pricing: {error}"]

    issues: List[str] = []
    for name, values in catalog["tiers"].items():
        have = pricing.TIERS.get(name)
        if have is None:
            issues.append(f"MISSING tier {name}: {values}")
            continue
        wanted = (values["input"], values["output"], values["cache_write_5m"],
                  values["cache_write_1h"], values["cache_read"], values["web_search"])
        mine = (have.input, have.output, have.cw_5m, have.cw_1h, have.cache_read, have.web_search)
        if wanted != mine:
            issues.append(f"CHANGED tier {name}: binary={wanted} table={mine}")
    for name in pricing.TIERS:
        if name not in catalog["tiers"]:
            issues.append(f"STALE tier {name} is no longer in the binary")
    for model in catalog["models"]:
        have = pricing.MODEL_TIERS.get(model["id"])
        if have is None:
            issues.append(f"MISSING model {model['id']} -> {model['pricing']}")
        elif have != model["pricing"]:
            issues.append(f"CHANGED model {model['id']}: binary={model['pricing']} table={have}")
        if model["window"]:
            window = pricing.CONTEXT_WINDOWS.get(model["id"])
            if window != model["window"]:
                issues.append(f"CHANGED window {model['id']}: binary={model['window']} table={window}")
    for model_id in pricing.MODEL_TIERS:
        if not any(m["id"] == model_id for m in catalog["models"]):
            issues.append(f"STALE model {model_id} is no longer in the binary")
    fast = catalog.get("fast_mode_tiers") or {}
    have_fast = dict(getattr(pricing, "FAST_MODE_TIERS", {}))
    if fast and fast != have_fast:
        for model_id, tier_name in sorted(fast.items()):
            if have_fast.get(model_id) != tier_name:
                issues.append(f"CHANGED fast-mode branch {model_id}: binary={tier_name} "
                              f"table={have_fast.get(model_id)}")
        for model_id in sorted(set(have_fast) - set(fast)):
            issues.append(f"STALE fast-mode branch {model_id} is no longer in the binary")
    geo = catalog.get("geo_multipliers") or {}
    have_geo = dict(getattr(pricing, "INFERENCE_GEO_MULTIPLIERS", {}))
    if geo and geo != have_geo:
        issues.append(f"CHANGED inference-geo multipliers: binary={geo} table={have_geo}")
    return issues


def write_block(catalog: Dict[str, Any]) -> bool:
    text = PRICING_PY.read_text(encoding="utf-8")
    start = text.find(BEGIN)
    end = text.find(END)
    if start < 0 or end < 0:
        raise SystemExit("markers not found in oe/pricing.py -- refusing to rewrite blindly")
    tail = text[end + len(END):]
    if tail.startswith("\n"):
        tail = tail[1:]
    updated = text[:start] + render_block(catalog) + tail
    if updated == text:
        return False
    backup = PRICING_PY.with_suffix(".py.bak")
    backup.write_text(text, encoding="utf-8")
    tmp = PRICING_PY.with_suffix(".py.tmp")
    tmp.write_text(updated, encoding="utf-8")
    tmp.replace(PRICING_PY)
    return True


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--binary", help="path to a specific Claude Code binary")
    parser.add_argument("--write", action="store_true", help="rewrite the block in oe/pricing.py")
    parser.add_argument("--json", action="store_true", help="print the catalog as JSON")
    parser.add_argument("--quiet", action="store_true", help="only print differences")
    args = parser.parse_args(argv)

    binary = Path(args.binary) if args.binary else newest_binary()
    if binary is None or not binary.exists():
        print("no Claude Code binary found under", VERSIONS_DIR, file=sys.stderr)
        return 2

    catalog = extract(binary)
    if args.json:
        print(json.dumps(catalog, indent=2, sort_keys=True))
        return 0

    issues = compare(catalog)
    if not args.quiet:
        print(render_block(catalog))
    print(f"# source: {catalog['binary']} "
          f"({len(catalog['tiers'])} tiers, {len(catalog['models'])} models)", file=sys.stderr)
    if issues:
        print("# pricing table differs from the installed binary:", file=sys.stderr)
        for issue in issues:
            print("#   " + issue, file=sys.stderr)
    else:
        print("# pricing table matches the installed binary", file=sys.stderr)

    if args.write:
        changed = write_block(catalog)
        print("# oe/pricing.py " + ("updated (backup at oe/pricing.py.bak)" if changed
                                    else "already up to date"), file=sys.stderr)
    return 1 if (issues and not args.write) else 0


if __name__ == "__main__":
    sys.exit(main())
