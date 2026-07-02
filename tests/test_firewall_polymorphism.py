from ipaddress import ip_address
from unittest.mock import patch

from ban_engine.firewall import DryRunBackend, LinuxIptablesBackend, WindowsFirewallBackend


def test_dry_run_backend_is_polymorphic():
    backend = DryRunBackend()
    ip = ip_address("203.0.113.10")

    backend.block_ip(ip)

    assert backend.is_blocked(ip)


def test_linux_backend_uses_iptables_commands():
    backend = LinuxIptablesBackend()
    ip = ip_address("203.0.113.10")
    with patch("subprocess.run") as run:
        run.return_value.returncode = 1
        backend.block_ip(ip)

    assert run.call_count >= 2
    assert "iptables" in run.call_args_list[-1].args[0][0]


def test_windows_backend_uses_netsh_commands():
    backend = WindowsFirewallBackend()
    ip = ip_address("203.0.113.10")
    with patch("subprocess.run") as run:
        run.return_value.returncode = 1
        backend.block_ip(ip)

    assert run.call_count >= 2
    assert run.call_args_list[-1].args[0][0] == "netsh"
