from __future__ import annotations

import math
import re

# Candidate tokens: long-ish strings that often represent secrets
TOKEN_RE = re.compile(r"[A-Za-z0-9_\-\/\+=]{20,}")

def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    ent = 0.0
    length = len(s)
    for c in freq.values():
        p = c / length
        ent -= p * math.log2(p)
    return ent

def looks_like_high_entropy_token(s: str) -> bool:
    # Heuristics to reduce noise:
    # - long enough
    # - reasonably high entropy
    if len(s) < 28:
        return False
    ent = shannon_entropy(s)
    return ent >= 4.0
