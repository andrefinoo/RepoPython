from datetime import datetime

from ban_engine.parser import SSHLogParser


def test_parse_failed_password_for_existing_user():
    parser = SSHLogParser()

    line = "Jun 25 10:15:32 server sshd[1234]: Failed password for root from 192.168.1.10 port 22 ssh2"

    attempt = parser.parse_line(line)

    assert attempt is not None
    assert attempt.ip == "192.168.1.10"
    assert attempt.username == "root"
    assert attempt.original_line == line
    assert isinstance(attempt.timestamp, datetime)


def test_parse_failed_password_for_invalid_user():
    parser = SSHLogParser()

    line = "Jun 25 10:16:00 server sshd[1235]: Failed password for invalid user admin from 203.0.113.5 port 22 ssh2"

    attempt = parser.parse_line(line)

    assert attempt is not None
    assert attempt.ip == "203.0.113.5"
    assert attempt.username == "admin"


def test_parse_invalid_user_line():
    parser = SSHLogParser()

    line = "Jun 25 10:17:20 server sshd[1236]: Invalid user test from 2001:db8::1 port 22"

    attempt = parser.parse_line(line)

    assert attempt is not None
    assert attempt.ip == "2001:db8::1"
    assert attempt.username == "test"


def test_parse_non_relevant_line_returns_none():
    parser = SSHLogParser()

    line = "Jun 25 10:18:00 server systemd[1]: Started Daily apt download activities."

    attempt = parser.parse_line(line)

    assert attempt is None


def test_parse_invalid_ip_returns_none():
    parser = SSHLogParser()

    line = "Jun 25 10:19:00 server sshd[1237]: Failed password for root from 999.999.999.999 port 22 ssh2"

    attempt = parser.parse_line(line)

    assert attempt is None


def test_parse_empty_line_returns_none():
    parser = SSHLogParser()

    attempt = parser.parse_line("")

    assert attempt is None


def test_parse_file_returns_only_valid_attempts(tmp_path):
    parser = SSHLogParser()

    log_file = tmp_path / "auth.log"
    log_file.write_text(
        "\n".join(
            [
                "Jun 25 10:15:32 server sshd[1234]: Failed password for root from 192.168.1.10 port 22 ssh2",
                "Jun 25 10:16:00 server sshd[1235]: Failed password for invalid user admin from 203.0.113.5 port 22 ssh2",
                "Jun 25 10:18:00 server systemd[1]: Started Daily apt download activities.",
            ]
        ),
        encoding="utf-8",
    )

    attempts = parser.parse_file(log_file)

    assert len(attempts) == 2
    assert attempts[0].ip == "192.168.1.10"
    assert attempts[1].ip == "203.0.113.5"