from __future__ import annotations

from collections import defaultdict
from datetime import timedelta

from .config import EngineConfig
from .firewall.base import FirewallBackend
from .models import LoginFailure
from .state import StateStore


class IncidentResponseEngine:
    """Motore centrale: usa FirewallBackend senza conoscere la sottoclasse concreta."""

    def __init__(self, backend: FirewallBackend, config: EngineConfig, state_store: StateStore | None = None) -> None:
        self.backend = backend
        self.config = config
        self.state_store = state_store

    def detect_offenders(self, events: list[LoginFailure]) -> dict[str, int]:
        grouped: dict[str, list[LoginFailure]] = defaultdict(list)
        for event in events:
            if self.config.is_whitelisted(event.ip):
                continue
            grouped[str(event.ip)].append(event)

        offenders: dict[str, int] = {}
        window = timedelta(minutes=self.config.window_minutes)
        for ip, ip_events in grouped.items():
            ordered = sorted(ip_events, key=lambda event: event.timestamp)
            for index, event in enumerate(ordered):
                in_window = [candidate for candidate in ordered[index:] if candidate.timestamp - event.timestamp <= window]
                if len(in_window) >= self.config.threshold:
                    offenders[ip] = len(in_window)
                    break
        return offenders

    def respond(self, events: list[LoginFailure]) -> dict[str, int]:
        offenders = self.detect_offenders(events)
        for ip, attempts in offenders.items():
            from ipaddress import ip_address
            parsed_ip = ip_address(ip)
            if not self.backend.is_blocked(parsed_ip):
                self.backend.block_ip(parsed_ip)
                if self.state_store is not None:
                    self.state_store.append_ban(ip, f"{attempts} failed SSH login attempts")
        return offenders
