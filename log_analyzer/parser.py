"""
Parser de logs de autenticación (interpreta formato syslog estándar 
de sshd y sudo, independiente del S.O. donde se ejecute el script).

Convierte líneas de texto crudas en objetos LogEvent estructurados, listos
para que los detectores los analicen.
"""
from __future__ import annotations

import re
from datetime import datetime
from typing import Optional
from dateclasses import dataclass, field

# El año no viene en el log clásico de syslog; se asume el año actual salvo
# que se indique otro con --year en el CLI.

_DEFAULT_YEAR = datetime.now().year

_SYSLOG_PREFIX = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<process>\S+?)(?:\[(?P<pid>\d+)\])?:\s*(?P<message>.*)$"
)

_FAILED_PASSWORD = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.]+) port (?P<port>\d+)">
)

_ACCEPTED_PASSWORD = re.compile(
    r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>[\d.]+) port (?P<port>\d+)"
)

_INVALID_USER = re.compile(
    r"Invalid user (?P<user>\S+) from (?P<ip>[\d.]+)(?: port (?P<port>\d+))?"
)

_SUDO_COMMAND = re.compile(
    r"(?P<user>\S+)\s*:\s*TTY=(?P<tty>\S+)\s*;\s*PWD=(?P<pwd>\S+)\s*;\s*"
    r"USER=(?P<target_user>\S+)\s*;\s*COMMAND=(?P<command>.*)"
)

_MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}

# Tipos de evento que el parser reconoce.
EVENT_FAILED_LOGIN = "failed_login"
EVENT_SUCCESSFUL_LOGIN = "successful_login"
EVENT_INVALID_USER = "invalid_user"
EVENT_SUDO_COMMAND = "sudo_command"
EVENT_UNKNOWN = "unknown"

@dataclass
class LogEvent:
    """
    Representa un evento de log de autenticación.
    """
    raw_line: str
    timestamp: Optional[datetime]
    host: str
    process: str
    event_type: str
    user: Optional[str] = None
    src_ip: Optional[str] = None
    port: Optional[int] = None
    extra: dict = field(default_factory=dict)

def _parse_timestamp(month: str, day: str, time_str: str, year: int = _DEFAULT_YEAR) -> Optional[datetime]:
    """
    Convierte los componentes de fecha y hora del log en un objeto datetime.
    """
    month_num = _MONTHS.get(month)
    if month_num is None:
        return None
    try:
        hour, minute, second = (int(part) for part in time_str.split(":"))
        return datetime(year, month_num, int(day), hour, minute, second)
    except ValueError:
        return None

def parse_line(line: str, year: int = _DEFAULT_YEAR) -> Optional[LogEvent]:
    """
    Convierte una línea cruda de auth.log en un LogEvent.

    Devuelve None si la línea no tiene el formato esperado (por ejemplo,
    líneas en blanco o de otro servicio que no interesa).
    """
    line = line.rstrip("\n")
    if not line.strip():
        return None

    prefix_match = _SYSLOG_PREFIX.match(line)
    if not prefix_match:
        return None

    parts = prefix_match.groupdict()
    timestamp = _parse_timestamp(parts["month"], parts["day"], parts["time"], year)
    host = parts["host"]
    process = parts["process"]
    message = parts["message"]

    if process == "sshd":
        failed = _FAILED_PASSWORD.search(message)
        if failed:
            return LogEvent(
                raw_line=line, timestamp=timestamp, host=host, process=process,
                event_type=EVENT_FAILED_LOGIN,
                user=failed.group("user"), src_ip=failed.group("ip"),
                port=int(failed.group("port")),
            )

        accepted = _ACCEPTED_PASSWORD.search(message)
        if accepted:
            return LogEvent(
                raw_line=line, timestamp=timestamp, host=host, process=process,
                event_type=EVENT_SUCCESSFUL_LOGIN,
                user=accepted.group("user"), src_ip=accepted.group("ip"),
                port=int(accepted.group("port")),
            )

        invalid = _INVALID_USER.search(message)
        if invalid:
            port = invalid.group("port")
            return LogEvent(
                raw_line=line, timestamp=timestamp, host=host, process=process,
                event_type=EVENT_INVALID_USER,
                user=invalid.group("user"), src_ip=invalid.group("ip"),
                port=int(port) if port else None,
            )

    elif process == "sudo":
        sudo_match = _SUDO_COMMAND.search(message)
        if sudo_match:
            return LogEvent(
                raw_line=line, timestamp=timestamp, host=host, process=process,
                event_type=EVENT_SUDO_COMMAND,
                user=sudo_match.group("user"),
                extra={
                    "target_user": sudo_match.group("target_user"),
                    "command": sudo_match.group("command"),
                    "tty": sudo_match.group("tty"),
                },
            )

    # Línea reconocida como syslog pero de un evento que no nos interesa
    # analizar (por ejemplo, "pam_unix(sshd:session): session opened").
    return LogEvent(
        raw_line=line, timestamp=timestamp, host=host, process=process,
        event_type=EVENT_UNKNOWN,
    )

def parse_file(path: str, year: int = _DEFAULT_YEAR):
    """
    Lee un archivo de log y devuelve una lista de LogEvent.
    """
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            event = parse_line(line, year)
            if event is not None:
                yield event