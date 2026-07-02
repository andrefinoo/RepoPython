from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from ipaddress import ip_address, IPv4Address, IPv6Address

IPAddress = IPv4Address | IPv6Address


@dataclass(frozen=True)
class LoginFailure:
    """Evento normalizzato prodotto dal parser dei log SSH."""

    timestamp: datetime
    ip: IPAddress
    username: str | None = None
    raw_line: str = ""


def parse_ip(value: str) -> IPAddress:
    """Valida una stringa come indirizzo IPv4/IPv6."""
    return ip_address(value)


def now_utc() -> datetime:
    return datetime.now(timezone.utc)
