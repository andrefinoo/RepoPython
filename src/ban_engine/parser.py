from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path

from ban_engine.models import LoginAttempt


class SSHLogParser:
    """
    Parser per log SSH/auth.log.

    Riconosce righe tipiche di fallimento login, ad esempio:
    - Failed password for root from 192.168.1.10 port 22 ssh2
    - Failed password for invalid user admin from 203.0.113.5 port 22 ssh2
    - Invalid user test from 2001:db8::1 port 22
    """

    FAILED_PASSWORD_PATTERN = re.compile(
        r"""
        ^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+
        (?P<host>\S+)\s+
        sshd\[\d+\]:\s+
        Failed\spassword\sfor\s
        (?:(?:invalid\suser)\s)?
        (?P<username>\S+)\s+
        from\s
        (?P<ip>\S+)
        """,
        re.VERBOSE,
    )

    INVALID_USER_PATTERN = re.compile(
        r"""
        ^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+
        (?P<host>\S+)\s+
        sshd\[\d+\]:\s+
        Invalid\suser\s
        (?P<username>\S+)\s+
        from\s
        (?P<ip>\S+)
        """,
        re.VERBOSE,
    )

    def parse_line(self, line: str) -> LoginAttempt | None:
        """
        Analizza una singola riga di log.

        Restituisce:
        - LoginAttempt se la riga rappresenta un tentativo fallito SSH;
        - None se la riga non è pertinente o non è valida.
        """
        line = line.strip()

        if not line:
            return None

        for pattern in (self.FAILED_PASSWORD_PATTERN, self.INVALID_USER_PATTERN):
            match = pattern.search(line)

            if match:
                timestamp = self._parse_timestamp(match.group("timestamp"))
                ip = match.group("ip")
                username = match.group("username")

                try:
                    return LoginAttempt(
                        timestamp=timestamp,
                        ip=ip,
                        username=username,
                        original_line=line,
                    )
                except ValueError:
                    return None

        return None

    def parse_file(self, path: str | Path) -> list[LoginAttempt]:
        """
        Analizza un file di log e restituisce solo i tentativi falliti validi.
        Le righe non pertinenti vengono ignorate senza crash.
        """
        attempts: list[LoginAttempt] = []
        log_path = Path(path)

        with log_path.open("r", encoding="utf-8") as file:
            for line in file:
                attempt = self.parse_line(line)
                if attempt is not None:
                    attempts.append(attempt)

        return attempts

    def _parse_timestamp(self, raw_timestamp: str) -> datetime:
        """
        Converte timestamp tipo 'Jun 25 10:15:32' in datetime.

        I log auth.log spesso non includono l'anno.
        Come fallback controllato viene usato l'anno corrente.
        Questa scelta va documentata nel manuale tecnico.
        """
        current_year = datetime.now().year
        timestamp_with_year = f"{current_year} {raw_timestamp}"

        return datetime.strptime(timestamp_with_year, "%Y %b %d %H:%M:%S")
