from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional


@dataclass
class ResponseCache:
    ts: float
    status: int
    headers: Dict[str, str]
    body: str
    content_type: Optional[str]
