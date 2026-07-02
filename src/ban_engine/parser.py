from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path

from .models import LoginFailure, parse_ip

SSH_FAILURE_PATTERNS = [
    re.compile(r"Failed password for invalid user (?P<user>\S+) from (?P<ip>\S+)"),
    re.compile(r"Failed password for (?P<user>\S+) from (?P<ip>\S+)"),
    re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>\S+)"),
]


def parse_syslog_timestamp(line: str, year: int | None = None) -> datetime:
    """Parsa timestamp tipo 'Jun 25 10:30:12'. Fallback: timestamp corrente UTC."""
    if year is None:
        year = datetime.now(timezone.utc).year
    prefix = line[:15]
    try:
        naive = datetime.strptime(f"{year} {prefix}", "%Y %b %d %H:%M:%S")
        return naive.replace(tzinfo=timezone.utc)
    except ValueError:
        return datetime.now(timezone.utc)


class SSHLogParser:
    """Parser dedicato ai log di autenticazione SSH."""

    def parse_line(self, line: str) -> LoginFailure | None:
        for pattern in SSH_FAILURE_PATTERNS:
            match = pattern.search(line)
            if not match:
                continue
            try:
                ip = parse_ip(match.group("ip"))
            except ValueError:
                return None
            return LoginFailure(
                timestamp=parse_syslog_timestamp(line),
                ip=ip,
                username=match.groupdict().get("user"),
                raw_line=line.rstrip(),
            )
        return None

    def parse_file(self, path: str | Path) -> list[LoginFailure]:
        events: list[LoginFailure] = []
        with Path(path).open("r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                event = self.parse_line(line)
                if event is not None:
                    events.append(event)
        return events
