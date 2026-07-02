from __future__ import annotations

import subprocess
from ipaddress import IPv4Address, IPv6Address

from .base import FirewallBackend

IPAddress = IPv4Address | IPv6Address


class LinuxIptablesBackend(FirewallBackend):
    """Backend Linux basato su iptables."""

    def _run(self, command: list[str]) -> subprocess.CompletedProcess[str]:
        return subprocess.run(command, check=True, text=True, capture_output=True)

    def block_ip(self, ip: IPAddress) -> None:
        if self.is_blocked(ip):
            return
        self._run(["iptables", "-A", "INPUT", "-s", str(ip), "-j", "DROP", "-m", "comment", "--comment", self.rule_name])

    def unblock_ip(self, ip: IPAddress) -> None:
        self._run(["iptables", "-D", "INPUT", "-s", str(ip), "-j", "DROP"])

    def is_blocked(self, ip: IPAddress) -> bool:
        result = subprocess.run(
            ["iptables", "-C", "INPUT", "-s", str(ip), "-j", "DROP"],
            text=True,
            capture_output=True,
        )
        return result.returncode == 0
