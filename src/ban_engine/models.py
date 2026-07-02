"""Domain models for the Automated Incident Response Ban Engine.

This module contains only domain objects and validation logic.
It does not know anything about CLI arguments, subprocess calls or firewall commands.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from ipaddress import IPv4Address, IPv6Address, ip_address

IPAddress = IPv4Address | IPv6Address


def is_valid_ip(candidate: str) -> bool:
    """Return True only if candidate is a valid IPv4 or IPv6 address."""

    try:
        ip_address(candidate)
    except ValueError:
        return False
    return True


@dataclass(frozen=True, slots=True)
class LoginAttempt:
    """Represents a failed login attempt parsed from an authentication log.

    Attributes:
        timestamp: Date and time of the failed login attempt.
        ip: Valid IPv4 or IPv6 address of the source host.
        username: Optional username used during the login attempt.
        original_line: Original log line, useful for audit and debugging.
    """

    timestamp: datetime
    ip: str | IPAddress
    username: str | None = None
    original_line: str = ""

    def __post_init__(self) -> None:
        """Validate the IP address even when the normal constructor is used."""

        try:
            ip_address(str(self.ip))
        except ValueError as exc:
            raise ValueError(f"Invalid IP address: {self.ip}") from exc

    @classmethod
    def create(
        cls,
        *,
        timestamp: datetime,
        ip: str,
        username: str | None = None,
        original_line: str = "",
    ) -> "LoginAttempt":
        """Create a LoginAttempt validating the IP address with ipaddress.

        Args:
            timestamp: Date and time of the event.
            ip: Candidate IPv4 or IPv6 address as string.
            username: Optional username from the log line.
            original_line: Original log line.

        Returns:
            A validated LoginAttempt instance.

        Raises:
            ValueError: If ip is not a valid IPv4 or IPv6 address.
        """

        return cls(
            timestamp=timestamp,
            ip=ip_address(ip),
            username=username,
            original_line=original_line,
        )

    @property
    def ip_text(self) -> str:
        """Return the IP address as a normalized string."""

        return str(self.ip)


@dataclass(frozen=True, slots=True)
class BanDecision:
    """Represents the decision to ban an IP address.

    The engine will create this object when an IP exceeds the configured threshold.
    Firewall backends will later consume this decision without changing domain logic.
    """

    ip: str | IPAddress
    attempts_count: int
    threshold: int
    first_attempt_at: datetime
    last_attempt_at: datetime
    reason: str
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def __post_init__(self) -> None:
        """Validate basic business rules even when the normal constructor is used."""

        try:
            ip_address(str(self.ip))
        except ValueError as exc:
            raise ValueError(f"Invalid IP address: {self.ip}") from exc

        if self.attempts_count < 1:
            raise ValueError("attempts_count must be greater than zero")
        if self.threshold < 1:
            raise ValueError("threshold must be greater than zero")
        if self.attempts_count < self.threshold:
            raise ValueError("attempts_count must be greater than or equal to threshold")
        if self.first_attempt_at > self.last_attempt_at:
            raise ValueError("first_attempt_at cannot be after last_attempt_at")

    @classmethod
    def create(
        cls,
        *,
        ip: str | IPAddress,
        attempts_count: int,
        threshold: int,
        first_attempt_at: datetime,
        last_attempt_at: datetime,
        reason: str | None = None,
    ) -> "BanDecision":
        """Create a BanDecision validating business values and the IP address."""

        parsed_ip = ip if isinstance(ip, (IPv4Address, IPv6Address)) else ip_address(ip)
        decision_reason = reason or (
            f"IP {parsed_ip} exceeded threshold: "
            f"{attempts_count}/{threshold} failed login attempts"
        )

        return cls(
            ip=parsed_ip,
            attempts_count=attempts_count,
            threshold=threshold,
            first_attempt_at=first_attempt_at,
            last_attempt_at=last_attempt_at,
            reason=decision_reason,
        )

    @property
    def ip_text(self) -> str:
        """Return the IP address as a normalized string."""

        return str(self.ip)