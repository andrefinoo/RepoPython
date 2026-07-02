from __future__ import annotations

from abc import ABC, abstractmethod
from ipaddress import IPv4Address, IPv6Address

IPAddress = IPv4Address | IPv6Address


class FirewallBackend(ABC):
    """Contratto comune per i backend firewall.

    Le sottoclassi concrete traducono le operazioni logiche in comandi di sistema.
    """

    def __init__(self, rule_name: str = "BanEngine") -> None:
        self.rule_name = rule_name

    @abstractmethod
    def block_ip(self, ip: IPAddress) -> None:
        raise NotImplementedError

    @abstractmethod
    def unblock_ip(self, ip: IPAddress) -> None:
        raise NotImplementedError

    @abstractmethod
    def is_blocked(self, ip: IPAddress) -> bool:
        raise NotImplementedError
