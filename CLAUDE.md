# Security Guard — Claude Code Context

## Proyecto
Herramienta de auditoría de ciberseguridad. Analiza proyectos completos, detecta vulnerabilidades, simula ataques y genera reportes PDF.

## Skills Instaladas (Trail of Bits)
Los siguientes skills están disponibles vía la carpeta `.claude/trailofbits-skills/`:

- **insecure-defaults** — detecta patrones fail-open (secretos con fallback, auth deshabilitada por defecto)
- **supply-chain-risk-auditor** — evalúa riesgo de dependencias
- **static-analysis** — análisis estático con CodeQL/Semgrep
- **fp-check** — verificación de falsos positivos
- **variant-analysis** — descubrimiento de variantes de vulnerabilidades
- **agentic-actions-auditor** — auditoría de GitHub Actions

Para usar un skill, referencia su SKILL.md en `.claude/trailofbits-skills/plugins/<nombre>/skills/<nombre>/SKILL.md`.

## Arquitectura

```
app.py                      — Flask web server (puerto 5000)
run.py                      — Launcher que bypasea cache de bytecode
security_guard.py           — CLI entry point
requirements.txt            — Dependencias Python
core/
  __init__.py               — Re-exports de core utilities
  github_fetcher.py         — Clonado de repos GitHub, helpers is_github_url/is_web_url
  pdf_generator.py          — Genera reportes PDF bilingüe (ES/EN) con ReportLab
  report_generator.py       — Reportes consola y HTML (modo CLI)
scanners/
  __init__.py               — Exporta todos los scanners
  base.py                   — Finding, ScanResult, Severity, Category, BaseScanner
  static_analyzer.py        — 25+ patrones de vulnerabilidad con root_cause/consequences
  secret_detector.py        — 30+ patrones de secretos con entropia Shannon
  dependency_scanner.py     — 51 CVEs (Python/JS/Ruby/Go) con semver parsing
  config_auditor.py         — Docker, CI/CD, cookies, CORS, HSTS
  insecure_defaults.py      — Metodología Trail of Bits: fail-open patterns
  attack_simulator.py       — 20 vectores de ataque con context-aware detection
  web_auditor.py            — Auditoría black-box de sitios web en vivo
templates/index.html        — UI dark-theme con score ring y PDF export
```

## Estructura Finding
```python
Finding(
  title, severity, category, file_path, line_number,
  code_snippet, description,
  root_cause,     # POR QUÉ existe la vulnerabilidad
  consequences,   # IMPACTO si es explotada
  recommendation, # Cómo corregirla
  cwe_id, attack_simulation
)
```

## Comandos útiles
```bash
# Iniciar servidor
python run.py

# Ejecutar un scan via API
curl -X POST http://localhost:5000/api/scan -H "Content-Type: application/json" -d '{"path": "/ruta/proyecto"}'

# Descargar PDF en español
curl http://localhost:5000/api/export/pdf?lang=es -o reporte.pdf
```

## Notas de desarrollo
- Siempre usar `run.py` (no `app.py` directamente) para evitar cache de bytecode
- Los patrones de `static_analyzer.py` usan `re.VERBOSE` — el `#` debe escaparse como `[#]`
- El word boundary `\b` es crítico para evitar falsos positivos (ej: `overrides` → `DES`)

## Mecanismos clave añadidos en sesiones recientes

### Marcador `# security-guard: ignore-file`
Definido en `scanners/base.py` (`IGNORE_FILE_MARKER`, `has_ignore_marker()`).
Cualquier archivo que lo declare en sus primeros 2 KB es ignorado por **todos**
los scanners. Aplicado a `scanners/*.py` y `core/secret_verifiers.py` para que
el tool pueda auditarse a sí mismo sin reportar sus propios patrones de
detección como vulnerabilidades reales. En `config_auditor.py` está parchado en
el choke-point `_read()` (cubre los 13+ `os.walk` de una sola vez).

### Aviso de repositorios privados
`core/github_fetcher.py` define `PrivateRepoError` y `check_repo_visibility()`.
Antes de clonar, hace pre-flight contra la GitHub API. Si el repo es privado
(o devuelve 404 anónimo) y no hay token, lanza `PrivateRepoError` con mensaje
accionable. El token se sanitiza (`***`) en cualquier `git stderr` capturado.

### Banner de alertas inline (UI)
`templates/index.html` define `.alert-banner` + `showAlert(msg, title)` /
`hideAlert()`. Reemplaza todos los `alert()` nativos del navegador. El JS
detecta automáticamente warnings de tipo "private repo" mediante regex sobre
`/private|token|PAT|401|403|404/i` y ajusta el título mostrado.

### Auto-scan limpio
Tras los cambios anteriores, `python security_guard.py .` sobre el propio
proyecto reporta **0 hallazgos** (vs. 75 originales). Cualquier hallazgo nuevo
en una re-ejecución es real, no un FP del propio tool auditándose.
