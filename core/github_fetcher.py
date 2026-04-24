"""GitHub repository fetcher — clones a repo to a temp directory for scanning."""

import os
import re
import shutil
import subprocess
import tempfile
import threading
import atexit
from typing import Optional

# Track temp dirs created so we can clean them on exit
_temp_dirs: list[str] = []
_lock = threading.Lock()


def _cleanup_all():
    """Remove all temp dirs on process exit."""
    with _lock:
        for d in _temp_dirs:
            try:
                if os.path.isdir(d):
                    shutil.rmtree(d, ignore_errors=True)
            except Exception:
                pass


atexit.register(_cleanup_all)


def parse_github_url(url: str) -> dict:
    """Parse a GitHub URL and return repo info.

    Accepts:
      https://github.com/owner/repo
      https://github.com/owner/repo.git
      https://github.com/owner/repo/tree/branch
      github.com/owner/repo
    """
    url = url.strip().rstrip("/")
    if not url.startswith("http"):
        url = "https://" + url

    # Match github.com/owner/repo[/tree/branch]
    m = re.match(
        r"https?://github\.com/([^/]+)/([^/?\s]+?)(?:\.git)?(?:/tree/([^/?\s]+))?(?:[/?#].*)?$",
        url,
        re.IGNORECASE,
    )
    if not m:
        raise ValueError(f"Cannot parse GitHub URL: {url}")

    owner, repo, branch = m.group(1), m.group(2), m.group(3)
    clone_url = f"https://github.com/{owner}/{repo}.git"
    return {
        "owner": owner,
        "repo": repo,
        "branch": branch,  # None = default branch
        "clone_url": clone_url,
        "display": f"{owner}/{repo}" + (f"@{branch}" if branch else ""),
    }


def clone_repo(
    url: str,
    token: Optional[str] = None,
    depth: int = 1,
    progress_callback=None,
) -> str:
    """Clone a GitHub repository to a temporary directory.

    Args:
        url:               GitHub repo URL
        token:             Optional GitHub Personal Access Token for private repos
        depth:             Shallow clone depth (1 = just latest commit, faster)
        progress_callback: Optional callable(message: str) for status updates

    Returns:
        Path to the temporary directory containing the cloned repo.

    Raises:
        ValueError: If URL is invalid
        RuntimeError: If git clone fails
    """
    info = parse_github_url(url)

    def log(msg: str):
        if progress_callback:
            progress_callback(msg)

    log(f"Preparing to clone {info['display']}...")

    # Build clone URL (inject token for private repos)
    clone_url = info["clone_url"]
    if token:
        clone_url = clone_url.replace("https://", f"https://{token}@")

    # Create temp directory
    tmp_dir = tempfile.mkdtemp(prefix="sg_github_")
    with _lock:
        _temp_dirs.append(tmp_dir)

    log(f"Cloning {info['display']} (shallow, depth={depth})...")

    # Build git command
    cmd = [
        "git", "clone",
        "--depth", str(depth),
        "--single-branch",
        "--no-tags",
        "--quiet",
    ]
    if info["branch"]:
        cmd += ["--branch", info["branch"]]
    cmd += [clone_url, tmp_dir]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120,  # 2 minutes max
        )
        if proc.returncode != 0:
            stderr = proc.stderr.strip()
            # Sanitize token from error messages
            if token:
                stderr = stderr.replace(token, "***")
            raise RuntimeError(
                f"git clone failed (exit {proc.returncode}): {stderr or 'No error output'}"
            )
    except subprocess.TimeoutExpired:
        raise RuntimeError("git clone timed out after 120 seconds. Repository may be too large.")
    except FileNotFoundError:
        raise RuntimeError("git is not installed or not in PATH. Install git to use GitHub scanning.")

    log(f"Clone complete: {tmp_dir}")

    # Count files cloned
    file_count = sum(len(files) for _, _, files in os.walk(tmp_dir))
    log(f"Cloned {file_count:,} files")

    return tmp_dir


def cleanup_temp_dir(tmp_dir: str):
    """Explicitly remove a temp directory created by clone_repo."""
    try:
        if os.path.isdir(tmp_dir):
            shutil.rmtree(tmp_dir, ignore_errors=True)
        with _lock:
            if tmp_dir in _temp_dirs:
                _temp_dirs.remove(tmp_dir)
    except Exception:
        pass


def is_github_url(text: str) -> bool:
    """Return True if text looks like a GitHub URL."""
    text = text.strip().lower()
    return "github.com/" in text


def is_web_url(text: str) -> bool:
    """Return True if text looks like an HTTP/HTTPS URL (non-GitHub)."""
    text = text.strip().lower()
    return (
        text.startswith("http://") or text.startswith("https://")
    ) and "github.com" not in text
