from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml


@dataclass
class AminScanConfig:
    fail_on: str = "high"
    entropy: bool = True
    url: Optional[str] = None
    out_md: Optional[str] = None
    out_json: Optional[str] = None
    extra_ignores: List[str] = field(default_factory=list)


def load_config(base: Path) -> AminScanConfig:
    cfg_path = base / ".aminscan.yml"
    if not cfg_path.exists():
        return AminScanConfig()

    raw: Dict[str, Any] = yaml.safe_load(cfg_path.read_text(encoding="utf-8")) or {}

    return AminScanConfig(
        fail_on=str(raw.get("fail_on", "high")),
        entropy=bool(raw.get("entropy", True)),
        url=raw.get("url"),
        out_md=raw.get("out_md"),
        out_json=raw.get("out_json"),
        extra_ignores=list(raw.get("extra_ignores", []) or []),
    )
