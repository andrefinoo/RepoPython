from __future__ import annotations

import subprocess
from ipaddress import IPv4Address, IPv6Address

from .base import FirewallBackend

IPAddress = IPv4Address | IPv6Address


class WindowsFirewallBackend(FirewallBackend):
    """Backend Windows basato su netsh advfirewall."""

    def _rule_for(self, ip: IPAddress) -> str:
        return f"{self.rule_name}-{ip}"

    def _run(self, command: list[str]) -> subprocess.CompletedProcess[str]:
        return subprocess.run(command, check=True, text=True, capture_output=True)

    def block_ip(self, ip: IPAddress) -> None:
        if self.is_blocked(ip):
            return
        self._run([
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={self._rule_for(ip)}", "dir=in", "action=block", f"remoteip={ip}",
        ])

    def unblock_ip(self, ip: IPAddress) -> None:
        self._run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={self._rule_for(ip)}"])

    def is_blocked(self, ip: IPAddress) -> bool:
        result = subprocess.run(
            ["netsh", "advfirewall", "firewall", "show", "rule", f"name={self._rule_for(ip)}"],
            text=True,
            capture_output=True,
        )
        return result.returncode == 0
