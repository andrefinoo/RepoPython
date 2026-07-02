from __future__ import annotations

import json
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path


@dataclass
class BanRecord:
    ip: str
    reason: str
    banned_at: str


class StateStore:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def load(self) -> list[BanRecord]:
        if not self.path.exists():
            return []
        data = json.loads(self.path.read_text(encoding="utf-8"))
        return [BanRecord(**item) for item in data.get("bans", [])]

    def save(self, records: list[BanRecord]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {"bans": [asdict(record) for record in records]}
        self.path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    def append_ban(self, ip: str, reason: str) -> None:
        records = self.load()
        if any(record.ip == ip for record in records):
            return
        records.append(BanRecord(ip=ip, reason=reason, banned_at=datetime.now(timezone.utc).isoformat()))
        self.save(records)
