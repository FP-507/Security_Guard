# Backward-compatibility shim — logic lives in core/report_generator.py
from core.report_generator import (  # noqa: F401
    print_console_report,
    generate_html_report,
    calculate_security_score,
    get_grade,
)
