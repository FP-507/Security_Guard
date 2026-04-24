# Backward-compatibility shim — logic lives in core/github_fetcher.py
from core.github_fetcher import (  # noqa: F401
    parse_github_url,
    clone_repo,
    cleanup_temp_dir,
    is_github_url,
    is_web_url,
)
