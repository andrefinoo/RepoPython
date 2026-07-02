from datetime import datetime, timezone

import pytest

from ban_engine.models import BanDecision, LoginAttempt, is_valid_ip


def test_login_attempt_accepts_valid_ipv4():
    attempt = LoginAttempt.create(
        timestamp=datetime(2026, 7, 2, 10, 0, tzinfo=timezone.utc),
        ip="192.168.1.10",
        username="admin",
        original_line="Failed password for admin from 192.168.1.10 port 22 ssh2",
    )

    assert attempt.ip_text == "192.168.1.10"
    assert attempt.username == "admin"


def test_login_attempt_accepts_valid_ipv6():
    attempt = LoginAttempt.create(
        timestamp=datetime(2026, 7, 2, 10, 0, tzinfo=timezone.utc),
        ip="2001:db8::1",
    )

    assert attempt.ip_text == "2001:db8::1"


def test_login_attempt_rejects_invalid_ip():
    with pytest.raises(ValueError):
        LoginAttempt.create(
            timestamp=datetime(2026, 7, 2, 10, 0, tzinfo=timezone.utc),
            ip="999.999.999.999",
        )


def test_is_valid_ip():
    assert is_valid_ip("10.0.0.1") is True
    assert is_valid_ip("::1") is True
    assert is_valid_ip("not-an-ip") is False


def test_ban_decision_tracks_reason_and_threshold():
    first = datetime(2026, 7, 2, 10, 0, tzinfo=timezone.utc)
    last = datetime(2026, 7, 2, 10, 5, tzinfo=timezone.utc)

    decision = BanDecision.create(
        ip="203.0.113.5",
        attempts_count=5,
        threshold=3,
        first_attempt_at=first,
        last_attempt_at=last,
    )

    assert decision.ip_text == "203.0.113.5"
    assert decision.attempts_count == 5
    assert decision.threshold == 3
    assert "exceeded threshold" in decision.reason


def test_ban_decision_rejects_count_below_threshold():
    first = datetime(2026, 7, 2, 10, 0, tzinfo=timezone.utc)
    last = datetime(2026, 7, 2, 10, 5, tzinfo=timezone.utc)

    with pytest.raises(ValueError):
        BanDecision.create(
            ip="203.0.113.5",
            attempts_count=2,
            threshold=3,
            first_attempt_at=first,
            last_attempt_at=last,
        )
