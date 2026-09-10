"""Model pricing, context windows and the exact cost formula Claude Code bills with.

The tables below are transcribed from the model catalog embedded in the Claude
Code binary (see extract_pricing.py, which regenerates this block). They are
kept as literals rather than parsed at runtime because the statusline and hooks
must not grep a multi-hundred-megabyte binary on every invocation.

Cost formula, verified against real cost-state records to six decimals:

    cost = input        * tier.input      / 1e6
         + output       * tier.output     / 1e6
         + cw_5m_tokens * tier.cw_5m      / 1e6
         + cw_1h_tokens * tier.cw_1h      / 1e6
         + cache_read   * tier.cache_read / 1e6
         + web_search_requests * tier.web_search
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, Optional, Tuple

# --- BEGIN GENERATED TABLE (extract_pricing.py --write rewrites this block) ---
PRICING_SOURCE_VERSION = "2.1.267"


@dataclass(frozen=True)
class Tier:
    """USD per 1M tokens, except web_search which is USD per request."""

    input: float
    output: float
    cw_5m: float
    cw_1h: float
    cache_read: float
    web_search: float


TIERS: Dict[str, Tier] = {
    "haiku_35": Tier(0.8, 4.0, 1.0, 1.6, 0.08, 0.01),
    "haiku_45": Tier(1.0, 5.0, 1.25, 2.0, 0.1, 0.01),
    "tier_2_10": Tier(2.0, 10.0, 2.5, 4.0, 0.2, 0.01),
    "tier_3_15": Tier(3.0, 15.0, 3.75, 6.0, 0.3, 0.01),
    "tier_5_25": Tier(5.0, 25.0, 6.25, 10.0, 0.5, 0.01),
    "tier_10_50": Tier(10.0, 50.0, 12.5, 20.0, 1.0, 0.01),
    "tier_10_50_cache_read_0_25": Tier(10.0, 50.0, 12.5, 20.0, 0.25, 0.01),
    "tier_15_75": Tier(15.0, 75.0, 18.75, 30.0, 1.5, 0.01),
    "fast_30_150": Tier(30.0, 150.0, 37.5, 60.0, 3.0, 0.01),
}

MODEL_TIERS: Dict[str, str] = {
    "claude-3-5-haiku": "haiku_35",
    "claude-haiku-4-5": "haiku_45",
    "claude-3-5-sonnet": "tier_3_15",
    "claude-3-7-sonnet": "tier_3_15",
    "claude-sonnet-4-0": "tier_3_15",
    "claude-sonnet-4-5": "tier_3_15",
    "claude-sonnet-4-6": "tier_3_15",
    "claude-sonnet-5": "tier_2_10",
    "claude-opus-4-0": "tier_15_75",
    "claude-opus-4-1": "tier_15_75",
    "claude-opus-4-5": "tier_5_25",
    "claude-opus-4-6": "tier_5_25",
    "claude-opus-4-7": "tier_5_25",
    "claude-opus-4-8": "tier_5_25",
    "claude-opus-5": "tier_5_25",
    "claude-fable-5": "tier_10_50",
    "claude-fable-5-1": "tier_10_50_cache_read_0_25",
    "claude-mythos-5": "tier_10_50",
    "claude-mythos-5-1": "tier_10_50_cache_read_0_25",
}

CONTEXT_WINDOWS: Dict[str, int] = {
    "claude-haiku-4-5": 200000,
    "claude-sonnet-4-0": 200000,
    "claude-sonnet-4-5": 200000,
    "claude-sonnet-4-6": 200000,
    "claude-sonnet-5": 1000000,
    "claude-opus-4-0": 200000,
    "claude-opus-4-1": 200000,
    "claude-opus-4-5": 200000,
    "claude-opus-4-6": 200000,
    "claude-opus-4-7": 1000000,
    "claude-opus-4-8": 1000000,
    "claude-opus-5": 1000000,
    "claude-fable-5": 1000000,
    "claude-fable-5-1": 1000000,
    "claude-mythos-5": 1000000,
    "claude-mythos-5-1": 1000000,
}

DISPLAY_NAMES: Dict[str, str] = {
    "claude-3-5-haiku": "Haiku 3.5",
    "claude-haiku-4-5": "Haiku 4.5",
    "claude-3-5-sonnet": "Sonnet 3.5",
    "claude-3-7-sonnet": "Sonnet 3.7",
    "claude-sonnet-4-0": "Sonnet 4",
    "claude-sonnet-4-5": "Sonnet 4.5",
    "claude-sonnet-4-6": "Sonnet 4.6",
    "claude-sonnet-5": "Sonnet 5",
    "claude-opus-4-0": "Opus 4",
    "claude-opus-4-1": "Opus 4.1",
    "claude-opus-4-5": "Opus 4.5",
    "claude-opus-4-6": "Opus 4.6",
    "claude-opus-4-7": "Opus 4.7",
    "claude-opus-4-8": "Opus 4.8",
    "claude-opus-5": "Opus 5",
    "claude-fable-5": "Fable 5",
    "claude-fable-5-1": "Fable 5.1",
    "claude-mythos-5": "Mythos 5",
    "claude-mythos-5-1": "Mythos 5.1",
}

# Every `usage.speed === "fast"` branch of the per-request price resolver
# (minified `o5t`), NOT the display helper `Oke` -- Oke knows only the
# Opus 5 / 4.8 pair and reading it drops the 4.6 / 4.7 branch entirely.
FAST_MODE_TIERS: Dict[str, str] = {
    "claude-opus-4-6": "fast_30_150",
    "claude-opus-4-7": "fast_30_150",
    "claude-opus-4-8": "tier_10_50",
    "claude-opus-5": "tier_10_50",
}
FAST_MODE_MODELS = tuple(FAST_MODE_TIERS)
FAST_MODE_TIER = "tier_10_50"  # retained for callers that predate the map

# `Nke` multiplies the TOKEN part of the cost (not the per-request web-search
# charge) by `Tee(usage)`.
INFERENCE_GEO_MULTIPLIERS: Dict[str, float] = {
    "us": 1.1,
}
# --- END GENERATED TABLE ---

DEFAULT_CONTEXT_WINDOW = 200000

# A transcript records these as an assistant message whose model is the literal
# string "<synthetic>": client-side error placeholders with all-zero usage.
# They are billable-shaped but never billed, so they are known-free, not unpriced.
SYNTHETIC_MODELS = ("<synthetic>", "synthetic", "")

_DATE_SUFFIX = re.compile(r"-\d{8}$")
_BRACKET_SUFFIX = re.compile(r"\[[^\]]*\]\s*$")
_PROVIDER_PREFIX = re.compile(r"^(?:us|eu|apac)\.anthropic\.")


def normalize_model(model_id: Optional[str]) -> str:
    """Reduce a wire model id to a catalog key.

    Strips a bracket suffix ('claude-opus-5[1m]'), a provider prefix
    ('us.anthropic.claude-haiku-4-5'), a Bedrock version tail (':0') and a
    trailing release date ('-20251001'). The 1M-context suffix maps to the same
    tier -- Opus 5 has a 1M window at standard pricing, no long-context premium.
    """
    if not model_id:
        return ""
    name = str(model_id).strip()
    name = _BRACKET_SUFFIX.sub("", name).strip()
    name = _PROVIDER_PREFIX.sub("", name)
    if "@" in name:  # vertex style: claude-haiku-4-5@20251001
        name = name.split("@", 1)[0]
    if ":" in name:  # bedrock style: ...-v1:0
        name = name.split(":", 1)[0]
    name = re.sub(r"-v\d+$", "", name)
    name = _DATE_SUFFIX.sub("", name)
    return name


def is_synthetic(model_id: Optional[str]) -> bool:
    return normalize_model(model_id) in SYNTHETIC_MODELS


def tier_for(model_id: Optional[str], speed: str = "standard") -> Tuple[Optional[Tier], str]:
    """(tier, tier_name) for a model, applying the fast-mode override.

    Returns (None, 'unknown') for a model the catalog does not know, so callers
    can mark the call unpriced instead of silently charging it zero.
    """
    name = normalize_model(model_id)
    if name in SYNTHETIC_MODELS:
        return None, "synthetic"
    # `speed` arrives straight off a transcript's usage block, so it is not
    # guaranteed to be a string: `(speed or "").lower()` raised AttributeError
    # on a dict and took the entire ledger load down with it.
    if isinstance(speed, str) and speed.lower() == "fast":
        override = FAST_MODE_TIERS.get(name)
        if override:
            return TIERS[override], override
    tier_name = MODEL_TIERS.get(name)
    if tier_name is None:
        return None, "unknown"
    return TIERS[tier_name], tier_name


def context_window(model_id: Optional[str]) -> int:
    return CONTEXT_WINDOWS.get(normalize_model(model_id), DEFAULT_CONTEXT_WINDOW)


def display_name(model_id: Optional[str]) -> str:
    name = normalize_model(model_id)
    return DISPLAY_NAMES.get(name, name or "unknown")


def _int(value) -> int:
    """Coerce a usage field that may be absent, null, or a float."""
    if value is None:
        return 0
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def split_cache_creation(usage: dict) -> Tuple[int, int]:
    """(5m, 1h) cache-write tokens, split exactly the way Claude Code bills it.

    The binary (minified `Eee`) does NOT read ephemeral_5m_input_tokens at all:

        r = usage.cache_creation_input_tokens ?? 0
        d = Math.min(usage.cache_creation?.ephemeral_1h_input_tokens ?? 0, r)
        if (no 1h price || d <= 0) return r at the 5m rate
        return d at the 1h rate + (r - d) at the 5m rate

    So the flat total is the base and the 5m half is the REMAINDER. Normally the
    two halves already sum to the total, which makes the distinction invisible --
    but if they ever disagree (a truncated split, a provider that omits the 5m
    field), reading the 5m field directly drops the difference on the floor and
    under-charges. Follow the biller, not the field.
    """
    usage = usage or {}
    total = _int(usage.get("cache_creation_input_tokens"))
    detail = usage.get("cache_creation")
    hour = 0
    if isinstance(detail, dict):
        hour = _int(detail.get("ephemeral_1h_input_tokens"))
        if not total:
            # No flat total to anchor to: fall back to the halves themselves.
            total = hour + _int(detail.get("ephemeral_5m_input_tokens"))
    hour = max(0, min(hour, total))
    return total - hour, hour


def geo_multiplier(usage: dict) -> float:
    """`Tee` in the binary: US inference carries a 10% premium on tokens."""
    geo = (usage or {}).get("inference_geo")
    if not isinstance(geo, str):
        return 1.0
    return INFERENCE_GEO_MULTIPLIERS.get(geo.lower(), 1.0)


def price(usage: dict, model_id: Optional[str], speed: str = "standard") -> dict:
    """Cost breakdown for one API request's usage record."""
    usage = usage or {}
    effective_speed = speed or usage.get("speed") or "standard"
    tier, tier_name = tier_for(model_id, effective_speed)

    five, hour = split_cache_creation(usage)
    server_tools = usage.get("server_tool_use") or {}
    searches = _int(server_tools.get("web_search_requests"))

    if tier is None:
        return {
            "input_usd": 0.0,
            "output_usd": 0.0,
            "cache_write_5m_usd": 0.0,
            "cache_write_1h_usd": 0.0,
            "cache_read_usd": 0.0,
            "web_search_usd": 0.0,
            "total_usd": 0.0,
            "tier": tier_name,
            "geo_multiplier": 1.0,
            # A synthetic placeholder genuinely costs nothing; an unrecognised
            # model is a table gap the report has to shout about.
            "unpriced": tier_name == "unknown",
        }

    # The geo premium applies to the four token terms only: in the binary,
    # web-search requests are added AFTER the multiplier.
    geo = geo_multiplier(usage)
    input_usd = _int(usage.get("input_tokens")) * tier.input / 1e6 * geo
    output_usd = _int(usage.get("output_tokens")) * tier.output / 1e6 * geo
    cw5_usd = five * tier.cw_5m / 1e6 * geo
    cw1_usd = hour * tier.cw_1h / 1e6 * geo
    read_usd = _int(usage.get("cache_read_input_tokens")) * tier.cache_read / 1e6 * geo
    search_usd = searches * tier.web_search

    return {
        "input_usd": input_usd,
        "output_usd": output_usd,
        "cache_write_5m_usd": cw5_usd,
        "cache_write_1h_usd": cw1_usd,
        "cache_read_usd": read_usd,
        "web_search_usd": search_usd,
        "total_usd": input_usd + output_usd + cw5_usd + cw1_usd + read_usd + search_usd,
        "tier": tier_name,
        "geo_multiplier": geo,
        "unpriced": False,
    }


def uncached_equivalent_usd(cache_read_tokens: int, model_id: Optional[str],
                            speed: str = "standard") -> float:
    """What those cache-read tokens would have cost as fresh input.

    This is the counterfactual behind the 'caching saved you $X' figure.
    """
    tier, _ = tier_for(model_id, speed)
    if tier is None:
        return 0.0
    return _int(cache_read_tokens) * tier.input / 1e6
