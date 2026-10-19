#!/usr/bin/env python3
"""
CLI del analizador de logs de autenticación.

Ejemplos de uso:
  python cli.py --log /var/log/auth.log --html reporte.html --csv reporte.csv
  python cli.py --log tests/fixtures/sample_auth.log --html reporte.html
  python cli.py --log auth.log --html reporte.html --abuseipdb-key TU_API_KEY
"""
from __future__ import annotations

import argparse
import sys
from datetime import datetime

from log_analyzer.parser import parse_file
from log_analyzer.detectors import run_all_detectors
from log_analyzer.report import write_csv, write_html


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Analiza un archivo de log de autenticación (auth.log) y detecta patrones de ataque."
    )
    parser.add_argument("--log", required=True, help="Ruta al archivo de log a analizar (formato auth.log).")
    parser.add_argument("--csv", help="Ruta donde escribir el reporte en CSV.")
    parser.add_argument("--html", help="Ruta donde escribir el reporte en HTML.")
    parser.add_argument("--year", type=int, default=datetime.now().year,
                         help="Año a asumir para las fechas del log (syslog no incluye el año). Default: año actual.")
    parser.add_argument("--brute-force-threshold", type=int, default=5,
                         help="Cantidad mínima de fallos desde la misma IP para marcar fuerza bruta. Default: 5.")
    parser.add_argument("--brute-force-window", type=int, default=120,
                         help="Ventana en segundos para contar los fallos de fuerza bruta. Default: 120.")
    parser.add_argument("--abuseipdb-key", help="API key de AbuseIPDB para enriquecer las IPs encontradas (opcional).")
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)

    if not args.csv and not args.html:
        print("Error: especifica al menos --csv o --html para generar un reporte.", file=sys.stderr)
        return 1

    try:
        events = list(parse_file(args.log, year=args.year))
    except FileNotFoundError:
        print(f"Error: no se encontró el archivo de log '{args.log}'.", file=sys.stderr)
        return 1

    print(f"Líneas reconocidas: {len(events)}")

    findings = run_all_detectors(
        events,
        brute_force_threshold=args.brute_force_threshold,
        brute_force_window=args.brute_force_window,
    )
    print(f"Hallazgos detectados: {len(findings)}")

    if args.abuseipdb_key:
        from log_analyzer.enrichment import enrich_findings, IPReputationError
        try:
            enrich_findings(findings, args.abuseipdb_key)
        except IPReputationError as exc:
            print(f"Aviso: no se pudo enriquecer con AbuseIPDB ({exc}). Continuando sin enriquecimiento.", file=sys.stderr)

    if args.csv:
        write_csv(findings, args.csv)
        print(f"Reporte CSV escrito en: {args.csv}")

    if args.html:
        write_html(findings, args.html, source_file=args.log)
        print(f"Reporte HTML escrito en: {args.html}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
