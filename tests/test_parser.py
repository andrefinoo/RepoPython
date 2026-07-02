from ban_engine.parser import SSHLogParser


def test_parser_extracts_ip_and_user_from_failed_password():
    line = "Jun 25 10:00:00 server sshd[1]: Failed password for invalid user admin from 203.0.113.10 port 22 ssh2"
    event = SSHLogParser().parse_line(line)

    assert event is not None
    assert str(event.ip) == "203.0.113.10"
    assert event.username == "admin"


def test_parser_ignores_unrelated_lines():
    assert SSHLogParser().parse_line("Accepted password for user from 10.0.0.1") is None
