"""
Detectores de patrones de ataque sobre una lista de LogEvent ya parseados.

Cada detector recibe la lista completa de eventos y devuelve una lista de
Finding (hallazgos), con severidad y una descripción lista para el reporte.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import timedelta
from typing import List

from .parser import (
    LogEvent,
    EVENT_FAILED_LOGIN,
    EVENT_SUCCESSFUL_LOGIN,
    EVENT_INVALID_USER,
    EVENT_SUDO_COMMAND,
)

SEVERITY_LOW = "low"
SEVERITY_MEDIUM = "medium"
SEVERITY_HIGH = "high"

@dataclass
class Finding:
    """
    Un hallazgo: un patrón sospechoso detectado en el log.
    """
    rule: str
    severity: str
    title: str
    description: str
    src_ip: str = ""
    user: str = ""
    first_seen: str = ""
    last_seen: str = ""
    event_count: int = 1
    events: List[LogEvent] = field(default_factory=list)
    evidence: List[str] = field(default_factory=list)

def detect_brute_force(
    events: List[LogEvent],
    threshold: int = 5,
    window_seconds: int = 120
) -> List[Finding]:
    """
    Detecta fuerza bruta: `threshold` o más intentos fallidos desde la misma
    IP dentro de una ventana de `window_seconds` segundos.

    Agrupa los fallos por IP, los ordena por tiempo, y desliza una ventana:
    si en algún punto hay `threshold` fallos cuya marca de tiempo cabe dentro
    de `window_seconds`, se reporta un único hallazgo por esa IP (no uno por
    cada ráfaga, para no inundar el reporte)
    """
    failed_by_ip: dict[str, List[LogEvent]] = defaultdict(list)
    for event in events:
        # Solo se pueden comparar fallos que tengan IP y marca temporal.
        if event.event_type == EVENT_FAILED_LOGIN and event.src_ip and event.timestamp:
            failed_by_ip[event.src_ip].append(event)

    findings: List[Finding] = []
    window = timedelta(seconds=window_seconds)

    for ip, ip_events in failed_by_ip.items():
        # Al ordenar, la ventana siempre avanza cronológicamente y nunca retrocede.
        ip_events.sort(key=lambda e: e.timestamp)
        triggered = False
        start = 0
        for end in range(len(ip_events)):
            # Descarta los eventos demasiado antiguos respecto al actual.
            while ip_events[end].timestamp - ip_events[start].timestamp > window:
                start += 1
            count_in_window = end - start + 1
            if count_in_window >= threshold:
                triggered = True
                break  # No necesitamos seguir, ya tenemos un hallazgo para esta IP
        
        if triggered:
            # Un hallazgo resume todos los fallos de la IP, aunque haya varias ráfagas.
            users = sorted({e.user for e in ip_events if e.user})
            findings.append(Finding(
                rule="brute_force",
                severity=SEVERITY_HIGH,
                title=f"Fuerza bruta detectada desde {ip}",
                description=(
                    f"Se detectaron {len(ip_events)} intentos fallidos de login desde la IP {ip} "
                    f"contra el/los usuario(s) {', '.join(users) or 'desconocido'},"
                    f"con al menos {threshold} fallos" 
                    f"en un período de {window_seconds} segundos."
                ),
                src_ip=ip,
                user=", ".join(users),
                first_seen=str(ip_events[0].timestamp),
                last_seen=str(ip_events[-1].timestamp),
                event_count=len(ip_events),
                evidence=[e.raw_line for e in ip_events[:5]],  # Solo los primeros 5 eventos como evidencia
            ))
    
    return findings

def detect_compromise_after_brute_force(
    events: List[LogEvent],
    fail_threshold: int = 3,
) -> List[Finding]:
    """
    Detecta compromisos después de fuerza bruta: si hay un hallazgo de fuerza bruta
    y luego un login exitoso desde la misma IP dentro de `compromise_window_seconds`
    segundos, se reporta como un hallazgo de compromiso.
    """
    by_ip_user: dict[tuple, List[LogEvent]] = defaultdict(list)
    for event in events:
        # Separar por IP y usuario evita mezclar intentos contra distintas cuentas.
        if event.event_type in (EVENT_FAILED_LOGIN, EVENT_SUCCESSFUL_LOGIN) and event.src_ip and event.user:
            by_ip_user[(event.src_ip, event.user)].append(event)

    findings: List[Finding] = []
    for (ip, user), seq in by_ip_user.items():
        seq.sort(key=lambda e: e.timestamp or 0)
        fail_streak = 0
        for event in seq:
            if event.event_type == EVENT_FAILED_LOGIN:
                fail_streak += 1
            elif event.event_type == EVENT_SUCCESSFUL_LOGIN:
                if fail_streak >= fail_threshold:
                    findings.append(Finding(
                        rule="compromise_after_brute_force",
                        severity=SEVERITY_HIGH,
                        title=f"Posible cuenta comprometida: {user}@{ip}",
                        description=(
                            f"{fail_streak} fallos de autenticación consecutivos "
                            f"desde {ip} contra el usuario {user}, seguidos de un "
                            f"login EXITOSO. Esto sugiere que la contraseña fue "
                            f"adivinada correctamente."
                        ),
                        src_ip=ip,
                        user=user,
                        first_seen=str(seq[0].timestamp),
                        last_seen=str(event.timestamp),
                        event_count=fail_streak + 1,
                        evidence=[event.raw_line],
                    ))
                # Un éxito cierra la racha, se haya generado hallazgo o no.
                fail_streak = 0
    return findings

def detect_invalid_user_scanning(
    events: List[LogEvent],
    threshold: int = 3,
) -> List[Finding]:
    """
    Detecta reconocimiento de usuarios: una misma IP probando `threshold` o
    más nombres de usuario DISTINTOS que no existen en el sistema. Es el
    patrón típico de un diccionario de usuarios (no solo de contraseñas).
    """
    users_by_ip: dict[str, set] = defaultdict(set)
    events_by_ip: dict[str, List[LogEvent]] = defaultdict(list)
    
    for event in events:
        if event.event_type == EVENT_INVALID_USER and event.src_ip:
            # El set cuenta nombres distintos; la lista conserva cada intento para la evidencia.
            users_by_ip[event.src_ip].add(event.user)
            events_by_ip[event.src_ip].append(event)

    findings: List[Finding] = []
    for ip, users in users_by_ip.items():
        if len(users) >= threshold:
            ip_events = events_by_ip[ip]
            ip_events.sort(key=lambda e: e.timestamp or 0)
            findings.append(Finding(
                rule="invalid_user_scanning",
                severity=SEVERITY_MEDIUM,
                title=f"Escaneo de usuarios inválidos desde {ip}",
                description=(
                    f"Se probaron {len(users)} nombres de usuario distintos que no "
                    f"existen en el sistema, desde la misma IP ({ip}): "
                    f"{', '.join(sorted(users))}."
                ),
                src_ip=ip,
                user=", ".join(sorted(users)),
                first_seen=str(ip_events[0].timestamp),
                last_seen=str(ip_events[-1].timestamp),
                event_count=len(ip_events),
                evidence=[e.raw_line for e in ip_events[:5]],  # Solo los primeros 5 eventos como evidencia
            ))
    
    return findings

def detect_privilege_escalation(
    events: List[LogEvent],
) -> List[Finding]:
    """
    Reporta cada uso de `sudo` hacia el usuario `root`, para que quede un
    registro auditable de comandos ejecutados con privilegios elevados.

    No todos los usos de sudo son maliciosos (es normal en administración),
    pero son el tipo de evento que un analista SOC debe poder revisar.
    """

    findings: List[Finding] = []
    for event in events:
        # Se audita sudo hacia root; otros usuarios destino no entran en esta regla.
        if event.event_type == EVENT_SUDO_COMMAND and event.extra.get("target_user") == "root":
            findings.append(Finding(
                rule="privilege_escalation",
                severity=SEVERITY_LOW,
                title=f"Comando ejecutado como root por {event.user}",
                description=(
                    f"El usuario {event.user} ejecutó un comando como root "
                    f"vía sudo: {event.extra.get('command')}"
                ),
                user=event.user or "",
                first_seen=str(event.timestamp),
                last_seen=str(event.timestamp),
                event_count=1,
                evidence=[event.raw_line],
            ))
    return findings

def run_all_detectors(
    events: List[LogEvent],
    brute_force_threshold: int = 5,
    brute_force_window: int = 120,
) -> List[Finding]:
    """
    Ejecuta todos los detectores sobre la lista de eventos y devuelve la
    lista completa de hallazgos.
    """
    findings: List[Finding] = []
    findings.extend(detect_brute_force(events, threshold=brute_force_threshold, window_seconds=brute_force_window))
    findings.extend(detect_compromise_after_brute_force(events))
    findings.extend(detect_invalid_user_scanning(events))
    findings.extend(detect_privilege_escalation(events))
    return findings