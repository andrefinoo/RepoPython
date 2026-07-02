from __future__ import annotations

import json
from dataclasses import dataclass
from ipaddress import ip_network, IPv4Network, IPv6Network
from pathlib import Path

Network = IPv4Network | IPv6Network


@dataclass(frozen=True)
class EngineConfig:
    threshold: int = 5
    window_minutes: int = 10
    whitelist: tuple[Network, ...] = ()

    @classmethod
    def from_json(cls, path: str | Path) -> "EngineConfig":
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        whitelist = tuple(ip_network(item, strict=False) for item in data.get("whitelist", []))
        return cls(
            threshold=int(data.get("threshold", 5)),
            window_minutes=int(data.get("window_minutes", 10)),
            whitelist=whitelist,
        )

    def is_whitelisted(self, ip: object) -> bool:
        return any(ip in network for network in self.whitelist)
