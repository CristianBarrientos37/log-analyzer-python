from log_analyzer.parser import parse_file
from log_analyzer.detectors import (
    detect_brute_force,
    detect_compromise_after_brute_force,
    detect_invalid_user_scanning,
    detect_privilege_escalation,
    run_all_detectors,
)

FIXTURE = "tests/fixtures/sample_auth.log"

def load_events():
    # Fijar el año evita que las fechas del fixture dependan del año actual.
    return list(parse_file(FIXTURE, year=2026))

def test_detect_brute_force_finds_the_attacking_ip():
    events = load_events()
    # El umbral debe identificar la IP que concentra los seis intentos fallidos.
    findings = detect_brute_force(events, threshold=5, window_seconds=120)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.src_ip == "10.10.10.40"
    assert finding.event_count == 6

def test_detect_brute_force_respects_threshold_and_window():
    events = load_events()
    # Un umbral imposible sirve para comprobar que no se generan falsos positivos.
    findings = detect_brute_force(events, threshold=50, window_seconds=120)
    assert findings == []  # No se detecta ningún ataque porque el umbral es demasiado alto


def test_detect_compromise_after_brute_force():
    events = load_events()
    # Verifica que una racha de fallos seguida de un éxito se atribuya a la misma cuenta e IP.
    findings = detect_compromise_after_brute_force(events, fail_threshold=3)
    assert len(findings) == 1
    assert findings[0].src_ip == "10.10.10.40"
    assert findings[0].user == "labuser"
    assert findings[0].severity == "high"


def test_detect_invalid_user_scanning():
    events = load_events()
    # El escaneo se cuenta por nombres inválidos distintos, pero el hallazgo conserva todos los eventos.
    findings = detect_invalid_user_scanning(events, threshold=3)
    assert len(findings) == 1
    assert findings[0].src_ip == "203.0.113.50"
    assert findings[0].event_count == 4


def test_detect_privilege_escalation_finds_both_sudo_commands():
    events = load_events()
    # Solo se reportan los comandos sudo dirigidos a root; la descripción incluye el comando.
    findings = detect_privilege_escalation(events)
    assert len(findings) == 2
    commands = {f.description for f in findings}
    assert any("/etc/shadow" in d for d in commands)


def test_run_all_detectors_combines_everything():
    events = load_events()
    # La función coordinadora debe incluir exactamente una clase de hallazgo por cada regla activa.
    findings = run_all_detectors(events)
    rules = {f.rule for f in findings}
    assert rules == {
        "brute_force",
        "compromise_after_brute_force",
        "invalid_user_scanning",
        "privilege_escalation",
    }
