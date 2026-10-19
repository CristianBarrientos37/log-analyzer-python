# Analizador de logs de autenticación en Python

Herramienta en Python puro (sin dependencias externas obligatorias) que analiza archivos de log de autenticación Linux (`auth.log`), detecta patrones de ataque comunes y genera un reporte en **CSV** y/o **HTML**.

> **Autor:** Cristian Barrientos 

---

## Qué detecta

| Detector | Qué busca | Severidad |
|---|---|---|
| `brute_force` | N intentos fallidos desde la misma IP en una ventana de tiempo corta | Alta |
| `compromise_after_brute_force` | Varios fallos consecutivos seguidos de un login **exitoso**, misma IP y usuario | Alta |
| `invalid_user_scanning` | Una misma IP probando varios nombres de usuario que no existen | Media |
| `privilege_escalation` | Todo uso de `sudo` hacia el usuario `root`, para auditoría | Baja |

Los umbrales (cuántos fallos, en cuántos segundos) son configurables por línea de comandos, no están fijos en el código.

## Por qué estos patrones

Son el equivalente, en texto, a lo que detecté con reglas de Wazuh en mi [laboratorio SOC](https://github.com/<tu-usuario>/wazuh-soc-lab): fuerza bruta SSH y escaneo de usuarios. Este proyecto construye esa misma lógica de detección desde cero en Python, sin depender de un SIEM, para mostrar cómo funciona el análisis de logs "por debajo" de una herramienta como Wazuh.

## Instalación

```bash
git clone https://github.com/<tu-usuario>/log-analyzer-python.git
cd log-analyzer-python
pip install -r requirements.txt   # solo necesario para correr las pruebas o usar --abuseipdb-key
```

El analizador en sí (`cli.py`) **no requiere ninguna dependencia externa** para funcionar; `requirements.txt` solo trae `pytest` (pruebas) y `requests` (enriquecimiento opcional de IPs).

## Uso

```bash
# Reporte HTML y CSV a la vez
python cli.py --log /var/log/auth.log --html reporte.html --csv reporte.csv

# Probar primero con el log de ejemplo incluido
python cli.py --log tests/fixtures/sample_auth.log --html reporte.html --year 2026

# Ajustar el umbral de fuerza bruta: 8 fallos en 90 segundos
python cli.py --log auth.log --html reporte.html --brute-force-threshold 8 --brute-force-window 90

# Con enriquecimiento de reputación de IP (requiere API key gratuita de AbuseIPDB)
python cli.py --log auth.log --html reporte.html --abuseipdb-key TU_API_KEY
```

Un ejemplo del reporte ya generado está en [`examples/reporte_ejemplo.html`](examples/reporte_ejemplo.html) (ábrelo directamente en el navegador) y [`examples/reporte_ejemplo.csv`](examples/reporte_ejemplo.csv).

### Opciones del CLI

| Flag | Descripción | Default |
|---|---|---|
| `--log` | Ruta al archivo de log a analizar (obligatorio) | — |
| `--csv` | Ruta de salida del reporte CSV | — |
| `--html` | Ruta de salida del reporte HTML | — |
| `--year` | Año a asumir (syslog no incluye año en la fecha) | año actual |
| `--brute-force-threshold` | Fallos mínimos desde una IP para marcar fuerza bruta | 5 |
| `--brute-force-window` | Ventana en segundos para contar los fallos | 120 |
| `--abuseipdb-key` | API key de AbuseIPDB para enriquecer las IPs (opcional) | — |

## Cómo funciona (arquitectura)

```
auth.log  →  parser.py  →  LogEvent[]  →  detectors.py  →  Finding[]  →  report.py  →  CSV / HTML
                                              ↑
                                    enrichment.py (opcional)
```

- **`parser.py`**: convierte cada línea cruda del log en un `LogEvent` estructurado (tipo de evento, usuario, IP, timestamp), usando expresiones regulares sobre el formato estándar de `sshd` y `sudo` en Ubuntu/Debian.
- **`detectors.py`**: recibe la lista de eventos y aplica cada regla de detección, devolviendo una lista de `Finding` con severidad, descripción y evidencia.
- **`enrichment.py`** (opcional): si se pasa una API key, consulta la reputación de cada IP encontrada contra AbuseIPDB.
- **`report.py`**: toma los `Finding` y los escribe como CSV o como una página HTML autocontenida (sin librerías externas, con estilos embebidos que se adaptan a modo claro/oscuro).

## Pruebas

```bash
pytest tests/ -v
```

16 pruebas unitarias cubren el parser (cada tipo de línea reconocida, líneas inválidas) y los 4 detectores (incluyendo casos negativos: que NO disparen por debajo del umbral).

## Limitaciones conocidas

- El parser está hecho para el formato de syslog clásico de Ubuntu/Debian (`sshd` y `sudo`). No procesa el formato journald binario directamente; si tu sistema usa journald, exporta primero con `journalctl -u ssh --since "..." > auth.log`.
- `brute_force` reporta un único hallazgo agregado por IP (no uno por cada ráfaga de 5 intentos), para no inundar el reporte en ataques largos.
- El enriquecimiento con AbuseIPDB es secuencial y sin caché persistente entre ejecuciones; para logs con muchas IPs distintas, cada ejecución vuelve a consultar todas.

## Posibles mejoras futuras

- Soporte para logs de Windows (exportados como CSV/EVTX) con el mismo motor de detección.
- Caché de resultados de AbuseIPDB en disco entre ejecuciones.
- Modo "watch" que analice un log en tiempo real (`tail -f`) en vez de un archivo cerrado.
- Exportar hallazgos directamente al formato de alertas de Wazuh, para comparar ambos enfoques sobre el mismo log.

## Estructura del repositorio

```text
log-analyzer-python/
├── README.md
├── requirements.txt
├── cli.py
├── log_analyzer/
│   ├── __init__.py
│   ├── parser.py
│   ├── detectors.py
│   ├── enrichment.py
│   └── report.py
├── tests/
│   ├── test_parser.py
│   ├── test_detectors.py
│   └── fixtures/
│       └── sample_auth.log
└── examples/
    ├── reporte_ejemplo.html
    └── reporte_ejemplo.csv
```

## Aviso

Este proyecto tiene fines educativos y de portafolio. El archivo de ejemplo (`tests/fixtures/sample_auth.log`) contiene datos sintéticos generados para el laboratorio, no logs reales de ningún sistema.
