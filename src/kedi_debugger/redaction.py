"""Shared name classification for non-secret model token metrics."""

from __future__ import annotations

import re

_TOKEN_METRIC_NAME = re.compile(
    r"(?:"
    r"(?:input|output|prompt|completion|total|cached|cache(?:read|write|creation)(?:input|output)?|"
    r"reasoning|audio|video|image|text|acceptedprediction|rejectedprediction|"
    r"tooluseprompt|candidates|thoughts|cachedcontent)"
    r"(?:tokens(?:details|limit)?|tokencount)|"
    r"(?:max|min)(?:input|output|prompt|completion|total)?tokens|"
    r"tokens?(?:usage|count|counts|budget|limit|used|remaining)"
    r")"
)


def is_token_metric_name(normalized: str) -> bool:
    """Recognize whole normalized metric names, never arbitrary token substrings."""
    return _TOKEN_METRIC_NAME.fullmatch(normalized) is not None
