from __future__ import annotations

from ipaddress import IPv4Address, IPv6Address

from .base import FirewallBackend

IPAddress = IPv4Address | IPv6Address


class DryRunBackend(FirewallBackend):
    """Backend non distruttivo: registra e stampa le azioni senza toccare il sistema."""

    def __init__(self, rule_name: str = "BanEngine") -> None:
        super().__init__(rule_name)
        self.blocked: set[str] = set()
        self.actions: list[str] = []

    def block_ip(self, ip: IPAddress) -> None:
        self.actions.append(f"DRY-RUN block {ip}")
        self.blocked.add(str(ip))
        print(f"[dry-run] block {ip}")

    def unblock_ip(self, ip: IPAddress) -> None:
        self.actions.append(f"DRY-RUN unblock {ip}")
        self.blocked.discard(str(ip))
        print(f"[dry-run] unblock {ip}")

    def is_blocked(self, ip: IPAddress) -> bool:
        return str(ip) in self.blocked
