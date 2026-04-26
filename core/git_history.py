"""Git history scanner — finds secrets that exist in commits even if the
working tree is clean.

A common mistake: a developer commits a secret, then deletes it in the next
commit and pushes. The secret is no longer in `HEAD`, but it's still in
`git log` and on every clone of the repo. Until the credential is rotated,
that history exposure is just as dangerous as a current leak.

This module walks the commit graph, fetches added/changed lines per blob,
and feeds them through the same pattern matchers as the working-tree scan.
"""

from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass
from typing import Iterator, Optional

# Hard cap on commits we walk to keep scans bounded — large monorepos can
# have 500k+ commits and hashing every blob isn't useful.
MAX_COMMITS = 2000

# Skip blobs above this size (vendored bundles, binaries committed by mistake).
MAX_BLOB_SIZE = 200_000


@dataclass
class HistoricalLine:
    commit: str        # short SHA
    author: str
    date: str          # ISO 8601
    file_path: str
    line_text: str     # the actual content of the added line


def is_git_repo(path: str) -> bool:
    """True if `path` is the root (or inside) a git repository."""
    return os.path.isdir(os.path.join(path, ".git")) or _git(path, "rev-parse", "--git-dir")[0] == 0


def _git(cwd: str, *args: str, timeout: float = 30.0) -> tuple[int, str, str]:
    """Run `git ARGS` in cwd. Returns (returncode, stdout, stderr)."""
    try:
        proc = subprocess.run(
            ["git", *args],
            cwd=cwd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )
        return proc.returncode, proc.stdout, proc.stderr
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return -1, "", ""


def iter_added_lines(repo_path: str, max_commits: int = MAX_COMMITS) -> Iterator[HistoricalLine]:
    """Yield every line ADDED in the last `max_commits` commits across all
    branches/refs. We only care about additions because removed lines are
    still present in the commit they were added in.

    Uses `git log -p` with diff filters so we don't have to parse the full
    blob ourselves — git already gives us per-line + tagged with file path.
    """
    if not is_git_repo(repo_path):
        return

    # `--all`: walk every ref, not just current branch.
    # `--no-merges`: merge commits don't add real content.
    # `-p --diff-filter=AM`: show patch for additions/modifications only.
    # `--unified=0`: no surrounding context, just the +/- lines.
    code, out, _ = _git(
        repo_path,
        "log", "--all", "--no-merges", "-p",
        "--diff-filter=AM", "--unified=0",
        f"--max-count={max_commits}",
        "--pretty=format:__COMMIT__%h%x00%an%x00%aI",
        timeout=120.0,
    )
    if code != 0 or not out:
        return

    commit = author = date = current_file = ""
    for raw in out.splitlines():
        if raw.startswith("__COMMIT__"):
            try:
                commit, author, date = raw[len("__COMMIT__"):].split("\x00", 2)
            except ValueError:
                commit = author = date = ""
            continue
        if raw.startswith("+++ b/"):
            current_file = raw[6:]
            continue
        if raw.startswith("--- ") or raw.startswith("diff ") or raw.startswith("index "):
            continue
        # Added lines start with `+` but skip the `+++` file headers (handled above).
        if raw.startswith("+") and not raw.startswith("+++"):
            text = raw[1:]
            if not text or len(text) > 1000:
                continue
            yield HistoricalLine(
                commit=commit,
                author=author,
                date=date,
                file_path=current_file,
                line_text=text,
            )


def get_blob_at_commit(repo_path: str, commit: str, path: str) -> Optional[str]:
    """Fetch a single file's content at a given commit. Used when a finding
    needs full context beyond the changed line."""
    code, out, _ = _git(repo_path, "show", f"{commit}:{path}", timeout=10.0)
    if code != 0 or len(out) > MAX_BLOB_SIZE:
        return None
    return out


def short_commit_url(commit: str, remote_url: Optional[str]) -> Optional[str]:
    """Build a clickable URL for the commit on GitHub/GitLab if we can
    detect the remote. Used to make findings actionable."""
    if not remote_url:
        return None
    url = remote_url.rstrip("/")
    if url.endswith(".git"):
        url = url[:-4]
    if url.startswith("git@github.com:"):
        url = "https://github.com/" + url[len("git@github.com:"):]
    if "github.com" in url or "gitlab.com" in url or "bitbucket.org" in url:
        return f"{url}/commit/{commit}"
    return None


def get_origin_url(repo_path: str) -> Optional[str]:
    code, out, _ = _git(repo_path, "config", "--get", "remote.origin.url", timeout=5.0)
    if code != 0:
        return None
    return out.strip() or None
