"""
EASM Scanner — Finding Data Model
Represents a security finding / exposure discovered during scanning.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any


SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


@dataclass
class Finding:
    """Represents a single security finding against a discovered asset."""

    rule_id: str
    name: str
    category: str
    severity: str                 # CRITICAL, HIGH, MEDIUM, LOW, INFO
    asset_value: str              # the asset this finding applies to
    asset_type: str               # domain, ip, port, url, etc.
    description: str = ""
    recommendation: str = ""
    cwe: str = ""
    cve: str = ""
    evidence: str = ""            # supporting evidence (banner, header, etc.)
    first_seen: str = ""
    last_seen: str = ""
    attributes: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        now = datetime.now(timezone.utc).isoformat()
        if not self.first_seen:
            self.first_seen = now
        if not self.last_seen:
            self.last_seen = now
        self.severity = self.severity.upper()

    @property
    def severity_rank(self) -> int:
        return SEVERITY_ORDER.get(self.severity, 99)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Finding:
        return cls(**{k: v for k, v in d.items()
                      if k in cls.__dataclass_fields__})

    def __repr__(self) -> str:
        return f"Finding({self.rule_id}, {self.severity}, {self.asset_value!r})"
