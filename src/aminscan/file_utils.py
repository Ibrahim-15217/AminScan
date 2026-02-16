from __future__ import annotations

from fnmatch import fnmatch
from pathlib import Path
from typing import Iterable, List

# Things we almost never want to scan
DEFAULT_IGNORES = [
    "**/.git/**",
    "**/node_modules/**",
    "**/dist/**",
    "**/build/**",
    "**/.venv/**",
    "**/__pycache__/**",
    "**/.pytest_cache/**",
    "**/*.min.js",
    "**/*.map",
    "**/*.lock",
]

# File types that usually contain readable text/code
TEXT_EXTS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".rb", ".php", ".cs", ".cpp", ".c", ".h",
    ".html", ".css", ".json", ".yml", ".yaml", ".toml", ".env", ".txt", ".md", ".ini", ".cfg",
}


def load_ignore_patterns(base: Path) -> List[str]:
    """
    Loads ignore patterns from DEFAULT_IGNORES and optional .aminscanignore file.
    """
    patterns = list(DEFAULT_IGNORES)
    ignore_file = base / ".aminscanignore"
    if ignore_file.exists():
        for line in ignore_file.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            patterns.append(line)
    return patterns


def is_ignored(rel_posix: str, patterns: List[str]) -> bool:
    """
    Checks if a file path (relative, posix-style) matches any ignore pattern.
    """
    for pat in patterns:
        if fnmatch(rel_posix, pat):
            return True
    return False


def iter_text_files(base: Path, ignore_patterns: List[str]) -> Iterable[Path]:
    """
    Iterates over text/code files under base that are not ignored.
    """
    for p in base.rglob("*"):
        if not p.is_file():
            continue
        rel = p.relative_to(base).as_posix()
        if is_ignored(rel, ignore_patterns):
            continue

        # Only scan text-like files; also allow no-extension small files
        if p.suffix.lower() in TEXT_EXTS or (p.suffix == "" and p.stat().st_size < 200_000):
            yield p
