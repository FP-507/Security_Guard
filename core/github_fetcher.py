"""GitHub repository fetcher — clones a repo to a temp directory for scanning.

Public surface
--------------
- :func:`parse_github_url`        — accept any of the common GitHub URL forms
- :func:`check_repo_visibility`   — call the GitHub REST API to learn if a repo
                                     is public, private, or missing (no auth required)
- :func:`clone_repo`              — shallow-clone a repo into a temp dir, with a
                                     pre-flight visibility check that produces a
                                     clear :class:`PrivateRepoError` when a token
                                     is needed but missing
- :func:`cleanup_temp_dir`        — explicitly remove a clone's temp dir
- :func:`is_github_url` / :func:`is_web_url` — input mode detection helpers

Cloned directories are tracked module-globally and removed on interpreter exit
via :mod:`atexit` so that crashed scans do not leak disk space.

Token sanitization
------------------
If a token is supplied, ``clone_repo`` strips it from any captured ``git`` stderr
before raising, so credentials never appear in error messages or logs.
"""

import json
import os
import re
import shutil
import subprocess
import tempfile
import threading
import atexit
import urllib.error
import urllib.request
from typing import Optional


class PrivateRepoError(RuntimeError):
    """Raised when the target repo is private (or does not exist) and no valid token was supplied."""

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


def check_repo_visibility(
    owner: str,
    repo: str,
    token: Optional[str] = None,
    timeout: int = 8,
) -> dict:
    """Query GitHub's REST API to learn whether a repo is public, private, or missing.

    Returns:
        {"status": "public"  | "private" | "not_found" | "unknown",
         "private": bool | None,
         "message": str}

    Never raises on network errors — falls back to "unknown" so the caller can
    still attempt the clone (and surface the real git error if it fails).
    """
    api_url = f"https://api.github.com/repos/{owner}/{repo}"
    req = urllib.request.Request(
        api_url,
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": "Security-Guard-Scanner",
            **({"Authorization": f"Bearer {token}"} if token else {}),
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="ignore"))
        is_private = bool(data.get("private"))
        return {
            "status": "private" if is_private else "public",
            "private": is_private,
            "message": "private repository" if is_private else "public repository",
        }
    except urllib.error.HTTPError as e:
        # 404 against the unauthenticated API can mean either "private" or "missing".
        if e.code in (401, 403, 404):
            return {
                "status": "not_found",
                "private": None,
                "message": (
                    f"GitHub API returned {e.code}: the repository is either PRIVATE "
                    f"or does not exist. If it is private, supply a GitHub Personal "
                    f"Access Token (PAT) with `repo` scope."
                ),
            }
        return {"status": "unknown", "private": None, "message": f"GitHub API error {e.code}"}
    except (urllib.error.URLError, TimeoutError, OSError, ValueError):
        return {"status": "unknown", "private": None, "message": "Could not reach GitHub API"}


def clone_repo(
    url: str,
    token: Optional[str] = None,
    depth: int = 1,
    progress_callback=None,
) -> str:
    """Clone a GitHub repository to a temporary directory.

    Performs a pre-flight visibility check via the GitHub API so that private
    repositories produce a clear, actionable error (asking for a PAT) instead
    of an opaque ``git clone`` failure.

    Args:
        url:               GitHub repo URL (any form accepted by ``parse_github_url``)
        token:             Optional GitHub Personal Access Token for private repos.
                           Required when the target is private; the token is
                           injected into the clone URL and stripped from any
                           error output.
        depth:             Shallow clone depth (1 = just latest commit, faster)
        progress_callback: Optional callable(message: str) for status updates;
                           used by the web UI to drive the progress label.

    Returns:
        Absolute path to the temporary directory containing the cloned repo.
        Caller should pass this to :func:`cleanup_temp_dir` when done.

    Raises:
        ValueError:        If the URL is not parseable as a GitHub repo URL.
        PrivateRepoError:  If the repo is private (or returns 404 anonymously)
                           and no valid token was supplied.
        RuntimeError:      For any other clone failure (network, timeout, missing
                           ``git`` binary, etc.).
    """
    info = parse_github_url(url)

    def log(msg: str):
        if progress_callback:
            progress_callback(msg)

    log(f"Preparing to clone {info['display']}...")

    # ── Pre-flight visibility check ───────────────────────────────────────
    # Detect private/missing repos *before* attempting to clone, so the user
    # gets a clear, actionable warning instead of an opaque git error.
    visibility = check_repo_visibility(info["owner"], info["repo"], token=token)
    if visibility["status"] == "private" and not token:
        raise PrivateRepoError(
            f"[!] WARNING: Repository '{info['display']}' is PRIVATE. "
            f"A GitHub Personal Access Token (PAT) with `repo` scope is required to scan it. "
            f"Generate one at https://github.com/settings/tokens and pass it via the token field."
        )
    if visibility["status"] == "not_found" and not token:
        raise PrivateRepoError(
            f"[!] WARNING: Repository '{info['display']}' could not be accessed anonymously "
            f"(GitHub API returned 404). It is either PRIVATE or does not exist. "
            f"If private, provide a GitHub Personal Access Token (PAT) with `repo` scope."
        )
    if visibility["status"] == "private" and token:
        log(f"[!] Note: '{info['display']}' is a PRIVATE repository — using supplied token.")

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
            # Detect auth failures from git itself (covers cases where the API
            # check returned "unknown" but the clone exposed the access issue).
            low = stderr.lower()
            if any(kw in low for kw in ("authentication failed", "could not read username",
                                        "repository not found", "403", "401")):
                raise PrivateRepoError(
                    f"[!] WARNING: Cannot access '{info['display']}'. The repository is "
                    f"PRIVATE or the supplied token is invalid/expired. "
                    f"Provide a GitHub Personal Access Token (PAT) with `repo` scope. "
                    f"(git: {stderr or 'no output'})"
                )
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
