"""
Enriquecimiento opcional de IPs contra la API gratuita de AbuseIPDB
(https://www.abuseipdb.com/). Requiere una API key gratuita (hasta 1000
consultas/día en el plan free).

Este módulo es opcional: si no se pasa --abuseipdb-key al CLI, nunca se
importa `requests` ni se hacen llamadas de red, para que el analizador
funcione sin conexión a internet.
"""
from __future__ import annotations

from typing import Optional


class IPReputationError(Exception):
    """Error al consultar la reputación de una IP."""


def check_ip_reputation(ip: str, api_key: str, timeout: int = 5) -> Optional[dict]:
    """
    Consulta la reputación de una IP en AbuseIPDB.

    Devuelve un diccionario con 'abuse_score' (0-100), 'country' y
    'total_reports', o None si la consulta falla (nunca lanza la excepción
    hacia el reporte: un fallo de red no debe tumbar todo el análisis).
    """
    try:
        import requests  # import local: solo se necesita si se usa enrichment
    except ImportError as exc:
        raise IPReputationError(
            "El paquete 'requests' no está instalado. Instálalo con: "
            "pip install requests"
        ) from exc

    try:
        response = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": api_key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=timeout,
        )
        response.raise_for_status()
        data = response.json()["data"]
        return {
            "abuse_score": data.get("abuseConfidenceScore"),
            "country": data.get("countryCode"),
            "total_reports": data.get("totalReports"),
            "isp": data.get("isp"),
        }
    except Exception:
        # Cualquier error de red, timeout o formato inesperado: se omite
        # el enriquecimiento para esa IP en vez de interrumpir el reporte.
        return None


def enrich_findings(findings, api_key: str) -> None:
    """
    Enriquece in-place cada Finding que tenga src_ip, agregando la
    reputación consultada a su diccionario `extra`-like (se guarda en
    finding.description como anexo, ya que Finding no tiene un campo
    dedicado para no acoplar el detector a este módulo opcional).
    """
    cache: dict[str, Optional[dict]] = {}
    for finding in findings:
        if not finding.src_ip:
            continue
        if finding.src_ip not in cache:
            cache[finding.src_ip] = check_ip_reputation(finding.src_ip, api_key)
        reputation = cache[finding.src_ip]
        if reputation:
            finding.description += (
                f" | Reputación AbuseIPDB: score {reputation['abuse_score']}/100, "
                f"{reputation['total_reports']} reportes, país {reputation['country']}."
            )
