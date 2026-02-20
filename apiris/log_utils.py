from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable, List


def ensure_dir(file_path: str | Path) -> Path:
    path = Path(file_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def append_jsonl(file_path: str | Path, payload: dict) -> bool:
    try:
        path = ensure_dir(file_path)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload) + "\n")
        return True
    except (OSError, ValueError):
        return False


def read_jsonl(file_path: str | Path) -> List[dict]:
    path = Path(file_path)
    if not path.exists():
        return []
    content = path.read_text(encoding="utf-8").strip()
    if not content:
        return []
    records: List[dict] = []
    for line in content.splitlines():
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return records
