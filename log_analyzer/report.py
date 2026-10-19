"""
Generación de reportes a partir de la lista de Finding.

Dos formatos, sin dependencias externas (csv y html están en la librería
estándar de Python; el HTML se arma con un template simple embebido):
  - CSV: para abrir en Excel/Sheets o cargar en otra herramienta.
  - HTML: para revisar de un vistazo en el navegador, con color por severidad.
"""
from __future__ import annotations

import csv
import html
from datetime import datetime
from typing import List

from .detectors import Finding, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW

_SEVERITY_ORDER = {SEVERITY_HIGH: 0, SEVERITY_MEDIUM: 1, SEVERITY_LOW: 2}
_SEVERITY_COLOR = {
    SEVERITY_HIGH: "#B42318",
    SEVERITY_MEDIUM: "#B54708",
    SEVERITY_LOW: "#3538CD",
}
_SEVERITY_LABEL_ES = {
    SEVERITY_HIGH: "Alta",
    SEVERITY_MEDIUM: "Media",
    SEVERITY_LOW: "Baja",
}


def _sorted_findings(findings: List[Finding]) -> List[Finding]:
    return sorted(findings, key=lambda f: (_SEVERITY_ORDER.get(f.severity, 99), f.first_seen))


def write_csv(findings: List[Finding], output_path: str) -> None:
    """Escribe los hallazgos en un archivo CSV, uno por fila."""
    fieldnames = [
        "rule", "severity", "title", "description",
        "src_ip", "user", "first_seen", "last_seen", "event_count",
    ]
    with open(output_path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for finding in _sorted_findings(findings):
            writer.writerow({
                "rule": finding.rule,
                "severity": finding.severity,
                "title": finding.title,
                "description": finding.description,
                "src_ip": finding.src_ip,
                "user": finding.user,
                "first_seen": finding.first_seen,
                "last_seen": finding.last_seen,
                "event_count": finding.event_count,
            })


def _finding_card_html(finding: Finding) -> str:
    color = _SEVERITY_COLOR.get(finding.severity, "#444")
    label = _SEVERITY_LABEL_ES.get(finding.severity, finding.severity)
    severity_class = finding.severity if finding.severity in _SEVERITY_COLOR else "unknown"
    evidence_html = "".join(
        f"<pre>{html.escape(line)}</pre>" for line in finding.evidence
    )
    return f"""
    <article class="finding severity-border--{severity_class}" data-severity="{html.escape(finding.severity, quote=True)}">
      <header class="finding-header">
        <span class="badge badge--{severity_class}" style="--severity-color:{color}">{html.escape(label)}</span>
        <span class="rule-name">{html.escape(finding.rule)}</span>
      </header>
      <h2>{html.escape(finding.title)}</h2>
      <p class="description">{html.escape(finding.description)}</p>
      <dl class="metadata">
        <div><dt>IP de origen</dt><dd>{html.escape(finding.src_ip or '-')}</dd></div>
        <div><dt>Usuario(s)</dt><dd>{html.escape(finding.user or '-')}</dd></div>
        <div><dt>Primera vez</dt><dd>{html.escape(finding.first_seen or '-')}</dd></div>
        <div><dt>Última vez</dt><dd>{html.escape(finding.last_seen or '-')}</dd></div>
        <div><dt>Eventos</dt><dd>{finding.event_count}</dd></div>
      </dl>
      {f"<details class=\"evidence\"><summary>Evidencia <span>({len(finding.evidence)} líneas)</span></summary><div class=\"evidence-list\">{evidence_html}</div></details>" if finding.evidence else ""}
    </article>
    """


def write_html(findings: List[Finding], output_path: str, source_file: str = "") -> None:
    """Escribe un reporte HTML autocontenido (sin dependencias externas)."""
    sorted_findings = _sorted_findings(findings)
    counts = {
        SEVERITY_HIGH: sum(1 for f in findings if f.severity == SEVERITY_HIGH),
        SEVERITY_MEDIUM: sum(1 for f in findings if f.severity == SEVERITY_MEDIUM),
        SEVERITY_LOW: sum(1 for f in findings if f.severity == SEVERITY_LOW),
    }
    cards_html = "".join(_finding_card_html(f) for f in sorted_findings)
    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    empty_state = """<section class="empty-state"><span class="empty-mark" aria-hidden="true">✓</span><h2>Sin hallazgos</h2><p>El análisis terminó sin detectar patrones que coincidan con las reglas activas.</p></section>""" if not findings else ""

    page = f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Reporte de análisis de logs</title>
<style>
  :root {{
    color-scheme: light;
    --bg: #f3f6f4; --surface: #ffffff; --ink: #202a25; --muted: #64716b;
    --border: #dce5df; --green: #176b52; --green-soft: #e5f2ec;
    --red: #b42318; --red-soft: #fff0ee; --amber: #a65b10; --amber-soft: #fff4e5;
  }}
  * {{ box-sizing: border-box; }}
  body {{ margin: 0; background: var(--bg); color: var(--ink); font-family: "Aptos", "Trebuchet MS", sans-serif; line-height: 1.5; }}
  .masthead {{ background: #203b32; color: #f4f8f5; border-bottom: 4px solid #82c5a2; }}
  .masthead-inner, main, footer {{ width: min(1120px, calc(100% - 40px)); margin: 0 auto; }}
  .masthead-inner {{ padding: 34px 0 30px; }}
  .eyebrow {{ margin: 0 0 7px; color: #b8d9c8; font-size: 12px; font-weight: 700; text-transform: uppercase; letter-spacing: 1px; }}
  h1 {{ margin: 0; font-size: 30px; line-height: 1.15; }}
  .report-meta {{ margin: 12px 0 0; color: #d5e5dc; font-size: 13px; }}
  .report-meta code {{ color: #fff; overflow-wrap: anywhere; }}
  main {{ padding: 28px 0 44px; }}
  .summary {{ display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 12px; margin-bottom: 28px; }}
  .metric {{ min-height: 100px; padding: 16px 18px; background: var(--surface); border: 1px solid var(--border); border-radius: 6px; }}
  .metric-label {{ display: block; color: var(--muted); font-size: 12px; font-weight: 700; text-transform: uppercase; }}
  .metric-count {{ display: block; margin-top: 5px; color: var(--ink); font-size: 29px; font-weight: 700; line-height: 1.1; font-variant-numeric: tabular-nums; }}
  .metric--high .metric-count {{ color: var(--red); }}
  .metric--medium .metric-count {{ color: var(--amber); }}
  .metric--low .metric-count {{ color: var(--green); }}
  .findings-toolbar {{ display: flex; align-items: center; justify-content: space-between; gap: 16px; margin-bottom: 16px; }}
  .findings-toolbar h2 {{ margin: 0; font-size: 18px; }}
  .search {{ width: min(320px, 100%); min-height: 40px; padding: 8px 12px; color: var(--ink); background: var(--surface); border: 1px solid #bac9c0; border-radius: 5px; font: inherit; }}
  .search:focus-visible, .filter:focus-visible, summary:focus-visible {{ outline: 3px solid #83c9a8; outline-offset: 2px; }}
  .filters {{ display: flex; flex-wrap: wrap; gap: 7px; margin-bottom: 18px; }}
  .filter {{ min-height: 34px; padding: 6px 11px; color: #46534c; background: transparent; border: 1px solid #cbd7d0; border-radius: 4px; font: inherit; font-size: 13px; cursor: pointer; }}
  .filter[aria-pressed="true"] {{ color: #fff; background: var(--green); border-color: var(--green); }}
  .filter-count {{ margin-left: 4px; font-variant-numeric: tabular-nums; opacity: .8; }}
  .finding-list {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(min(100%, 440px), 1fr)); gap: 14px; align-items: start; }}
  .finding {{ min-width: 0; padding: 18px; background: var(--surface); border: 1px solid var(--border); border-left: 4px solid #9aa79f; border-radius: 5px; box-shadow: 0 2px 7px #203b3209; }}
  .severity-border--high {{ border-left-color: var(--red); }}
  .severity-border--medium {{ border-left-color: #d28a29; }}
  .severity-border--low {{ border-left-color: var(--green); }}
  .finding-header {{ display: flex; align-items: center; gap: 9px; flex-wrap: wrap; }}
  .badge {{ display: inline-flex; align-items: center; min-height: 24px; padding: 2px 8px; color: #fff; background: var(--severity-color); border-radius: 3px; font-size: 11px; font-weight: 700; }}
  .badge--medium {{ color: #432500; }}
  .rule-name {{ color: var(--muted); font-family: ui-monospace, "Cascadia Code", monospace; font-size: 11px; overflow-wrap: anywhere; }}
  .finding h2 {{ margin: 12px 0 7px; font-size: 17px; line-height: 1.3; overflow-wrap: anywhere; }}
  .description {{ margin: 0; color: #4c5a52; font-size: 14px; overflow-wrap: anywhere; }}
  .metadata {{ display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 12px 16px; margin: 17px 0 0; padding-top: 14px; border-top: 1px solid #edf1ee; }}
  .metadata div {{ min-width: 0; }}
  .metadata dt {{ color: var(--muted); font-size: 11px; font-weight: 700; text-transform: uppercase; }}
  .metadata dd {{ margin: 2px 0 0; font-size: 13px; overflow-wrap: anywhere; font-variant-numeric: tabular-nums; }}
  .evidence {{ margin-top: 16px; border-top: 1px solid #edf1ee; }}
  .evidence summary {{ padding-top: 12px; color: var(--green); font-size: 13px; font-weight: 700; cursor: pointer; }}
  .evidence summary span {{ color: var(--muted); font-weight: 400; }}
  .evidence-list {{ display: grid; gap: 6px; margin-top: 10px; }}
  .evidence pre {{ max-width: 100%; margin: 0; padding: 10px; overflow-x: auto; color: #26332c; background: #f0f4f1; border: 1px solid #e1e9e3; border-radius: 3px; font: 12px/1.5 ui-monospace, "Cascadia Code", monospace; white-space: pre-wrap; overflow-wrap: anywhere; }}
  .empty-state {{ padding: 44px 20px; text-align: center; background: var(--surface); border: 1px solid var(--border); border-radius: 5px; }}
  .empty-mark {{ display: inline-grid; width: 38px; height: 38px; place-items: center; color: var(--green); background: var(--green-soft); border-radius: 50%; font-size: 22px; }}
  .empty-state h2 {{ margin: 12px 0 4px; font-size: 19px; }}
  .empty-state p, .no-results {{ margin: 0; color: var(--muted); }}
  .no-results {{ padding: 24px; text-align: center; background: var(--surface); border: 1px dashed #bac9c0; border-radius: 5px; }}
  footer {{ padding: 18px 0 24px; color: var(--muted); border-top: 1px solid var(--border); font-size: 12px; }}
  [hidden] {{ display: none !important; }}
  @media (max-width: 640px) {{
    .masthead-inner, main, footer {{ width: min(100% - 28px, 1120px); }}
    .masthead-inner {{ padding: 26px 0 24px; }}
    h1 {{ font-size: 25px; }}
    main {{ padding-top: 20px; }}
    .summary {{ grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 8px; margin-bottom: 24px; }}
    .metric {{ min-height: 84px; padding: 12px; }}
    .metric-count {{ font-size: 25px; }}
    .findings-toolbar {{ align-items: stretch; flex-direction: column; gap: 10px; }}
    .search {{ width: 100%; }}
    .finding {{ padding: 15px; }}
  }}
  @media print {{
    body {{ background: #fff; }}
    .masthead {{ color: #111; background: #fff; border-bottom: 2px solid #333; }}
    .eyebrow, .report-meta {{ color: #444; }}
    .report-meta code {{ color: #111; }}
    .findings-toolbar, .filters {{ display: none; }}
    .summary {{ grid-template-columns: repeat(4, 1fr); }}
    .finding {{ break-inside: avoid; box-shadow: none; }}
    details.evidence:not([open]) > *:not(summary) {{ display: block; }}
  }}
</style>
</head>
<body>
  <header class="masthead">
    <div class="masthead-inner">
      <p class="eyebrow">Centro de análisis · Seguridad</p>
      <h1>Reporte de análisis de logs</h1>
      <p class="report-meta">Archivo: <code>{html.escape(source_file) or '-'}</code> <span aria-hidden="true">·</span> Generado: {generated_at}</p>
    </div>
  </header>
  <main>
    <section class="summary" aria-label="Resumen por severidad">
      <div class="metric"><span class="metric-label">Hallazgos totales</span><span class="metric-count">{len(findings)}</span></div>
      <div class="metric metric--high"><span class="metric-label">Alta</span><span class="metric-count">{counts[SEVERITY_HIGH]}</span></div>
      <div class="metric metric--medium"><span class="metric-label">Media</span><span class="metric-count">{counts[SEVERITY_MEDIUM]}</span></div>
      <div class="metric metric--low"><span class="metric-label">Baja</span><span class="metric-count">{counts[SEVERITY_LOW]}</span></div>
    </section>
    {f'''<section class="findings-toolbar"><h2 id="findings-heading">Hallazgos</h2><input class="search" id="finding-search" type="search" placeholder="Buscar por IP, usuario o regla" aria-label="Buscar hallazgos"></section>
    <nav class="filters" aria-label="Filtrar por severidad">
      <button class="filter" type="button" data-filter="all" aria-pressed="true">Todos <span class="filter-count">{len(findings)}</span></button>
      <button class="filter" type="button" data-filter="high" aria-pressed="false">Alta <span class="filter-count">{counts[SEVERITY_HIGH]}</span></button>
      <button class="filter" type="button" data-filter="medium" aria-pressed="false">Media <span class="filter-count">{counts[SEVERITY_MEDIUM]}</span></button>
      <button class="filter" type="button" data-filter="low" aria-pressed="false">Baja <span class="filter-count">{counts[SEVERITY_LOW]}</span></button>
    </nav>
    <section class="finding-list" aria-labelledby="findings-heading">{cards_html}</section>
    <p class="no-results" id="no-results" hidden>No hay hallazgos que coincidan con la búsqueda y el filtro seleccionados.</p>{empty_state}''' if findings else empty_state}
  </main>
  <footer>Generado por log-analyzer.</footer>
  <script>
    const cards = [...document.querySelectorAll('.finding')];
    const search = document.querySelector('#finding-search');
    const noResults = document.querySelector('#no-results');
    const filters = [...document.querySelectorAll('.filter')];
    let activeFilter = 'all';

    if (search && noResults) {{
      function updateFindings() {{
        const query = search.value.trim().toLocaleLowerCase();
        let visibleCount = 0;
        for (const card of cards) {{
          const matchesSeverity = activeFilter === 'all' || card.dataset.severity === activeFilter;
          const matchesSearch = card.textContent.toLocaleLowerCase().includes(query);
          const visible = matchesSeverity && matchesSearch;
          card.hidden = !visible;
          if (visible) visibleCount += 1;
        }}
        noResults.hidden = visibleCount > 0 || cards.length === 0;
      }}

      search.addEventListener('input', updateFindings);
      for (const button of filters) {{
        button.addEventListener('click', () => {{
          activeFilter = button.dataset.filter;
          for (const filter of filters) filter.setAttribute('aria-pressed', String(filter === button));
          updateFindings();
        }});
      }}
    }}
  </script>
</body>
</html>"""

    with open(output_path, "w", encoding="utf-8") as handle:
        handle.write(page)
