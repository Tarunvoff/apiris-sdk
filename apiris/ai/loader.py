from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Optional


def load_json(path: str) -> Optional[Dict[str, Any]]:
    file_path = Path(path)
    if not file_path.exists():
        return None
    try:
        return json.loads(file_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None
