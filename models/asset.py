"""
EASM Scanner — Asset Data Model
Canonical representation for all discovered external assets.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class AssetType(str, Enum):
    DOMAIN = "domain"
    IP = "ip"
    PORT = "port"
    URL = "url"
    CERTIFICATE = "certificate"
    ASN = "asn"
    CIDR = "cidr"


@dataclass
class Asset:
    """Represents a single discovered external asset."""

    asset_type: str               # AssetType value
    value: str                    # e.g. "api.example.com", "203.0.113.50", "443"
    id: str = ""
    first_seen: str = ""
    last_seen: str = ""
    sources: list[str] = field(default_factory=list)
    attributes: dict[str, Any] = field(default_factory=dict)
    parent: str = ""              # parent asset value (e.g. domain for an IP)
    org_attribution: str = ""     # attributed organization
    confidence: float = 0.0       # attribution confidence 0.0-1.0

    def __post_init__(self) -> None:
        if not self.id:
            self.id = uuid.uuid4().hex[:12]
        now = datetime.now(timezone.utc).isoformat()
        if not self.first_seen:
            self.first_seen = now
        if not self.last_seen:
            self.last_seen = now

    def add_source(self, source: str) -> None:
        if source not in self.sources:
            self.sources.append(source)
        self.last_seen = datetime.now(timezone.utc).isoformat()

    def set_attr(self, key: str, value: Any) -> None:
        self.attributes[key] = value

    def get_attr(self, key: str, default: Any = None) -> Any:
        return self.attributes.get(key, default)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Asset:
        return cls(**{k: v for k, v in d.items()
                      if k in cls.__dataclass_fields__})

    def __hash__(self) -> int:
        return hash((self.asset_type, self.value, self.parent))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Asset):
            return NotImplemented
        return (self.asset_type == other.asset_type
                and self.value == other.value
                and self.parent == other.parent)

    def __repr__(self) -> str:
        return f"Asset({self.asset_type}, {self.value!r})"
