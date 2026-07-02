from datetime import datetime, timezone
from ipaddress import ip_address

from ban_engine.config import EngineConfig
from ban_engine.engine import IncidentResponseEngine
from ban_engine.firewall import DryRunBackend
from ban_engine.models import LoginFailure


def make_event(ip: str, minute: int) -> LoginFailure:
    return LoginFailure(
        timestamp=datetime(2026, 6, 25, 10, minute, tzinfo=timezone.utc),
        ip=ip_address(ip),
        username="root",
    )


def test_engine_detects_offender_over_threshold():
    backend = DryRunBackend()
    engine = IncidentResponseEngine(backend, EngineConfig(threshold=3, window_minutes=10))
    events = [make_event("203.0.113.10", 0), make_event("203.0.113.10", 1), make_event("203.0.113.10", 2)]

    offenders = engine.respond(events)

    assert offenders == {"203.0.113.10": 3}
    assert backend.is_blocked(ip_address("203.0.113.10"))


def test_engine_respects_whitelist():
    backend = DryRunBackend()
    from ipaddress import ip_network
    engine = IncidentResponseEngine(backend, EngineConfig(threshold=2, window_minutes=10, whitelist=(ip_network("203.0.113.10/32"),)))
    events = [make_event("203.0.113.10", 0), make_event("203.0.113.10", 1)]

    assert engine.respond(events) == {}
