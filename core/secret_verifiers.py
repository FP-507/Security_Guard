# security-guard: ignore-file
"""Live secret verification — TruffleHog-style.

For each secret type that exposes a cheap, read-only "whoami" endpoint, we
make a single HTTP call and report whether the credential is currently
ACTIVE. This is the difference between "looks like an AWS key" (regex hit)
and "this AWS key right now grants access to account 123456789012".

Every verifier:
  - Returns a `VerifyResult` with status VERIFIED / UNVERIFIED / UNKNOWN.
  - Times out fast (3s) so a scan never hangs.
  - Never sends the secret anywhere except the legitimate vendor endpoint.
  - Uses GET/HEAD or harmless metadata calls — no destructive operations.

Verification is OPT-IN (env: SECURITY_GUARD_VERIFY_SECRETS=1) because:
  1. It triggers vendor security alerts on the legitimate account owner.
  2. Some endpoints rate-limit aggressively.
  3. CI runs without network egress should not stall.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable, Optional
from urllib import request as _urlreq, error as _urlerr

VERIFY_TIMEOUT = 3.0
USER_AGENT = "security-guard/1.0 (+verification)"


@dataclass
class VerifyResult:
    """Outcome of a live verification attempt.

    - VERIFIED: vendor confirmed the credential is active (and may include
      extra metadata like account ID, scopes, owner email).
    - UNVERIFIED: vendor explicitly rejected (401/403). Token is invalid
      or revoked — still report it because it tells the user the secret
      WAS valid at some point.
    - UNKNOWN: network error / timeout / unexpected response. Don't change
      the finding.
    """
    status: str  # "VERIFIED" | "UNVERIFIED" | "UNKNOWN"
    detail: Optional[str] = None  # account ID, scopes, owner, etc.


def _is_enabled() -> bool:
    return os.environ.get("SECURITY_GUARD_VERIFY_SECRETS", "").lower() in ("1", "true", "yes")


def _request(url: str, headers: dict, method: str = "GET",
             body: Optional[bytes] = None) -> tuple[int, str]:
    """Returns (status_code, body_text). status=0 on network error."""
    try:
        req = _urlreq.Request(url, data=body, headers={**headers, "User-Agent": USER_AGENT}, method=method)
        with _urlreq.urlopen(req, timeout=VERIFY_TIMEOUT) as resp:
            return resp.status, resp.read().decode("utf-8", errors="replace")
    except _urlerr.HTTPError as e:
        try:
            text = e.read().decode("utf-8", errors="replace")
        except Exception:
            text = ""
        return e.code, text
    except (_urlerr.URLError, TimeoutError, OSError):
        return 0, ""


# ── GitHub ─────────────────────────────────────────────────────────────────

def verify_github_token(token: str) -> VerifyResult:
    """GET /user — returns 200 with user JSON if token is valid.
    Works for ghp_, gho_, ghu_, ghs_, ghr_."""
    code, body = _request("https://api.github.com/user", {"Authorization": f"token {token}"})
    if code == 200:
        try:
            user = json.loads(body)
            return VerifyResult("VERIFIED", f"login={user.get('login')} id={user.get('id')}")
        except json.JSONDecodeError:
            return VerifyResult("VERIFIED", "valid token, opaque response")
    if code in (401, 403):
        return VerifyResult("UNVERIFIED", f"vendor rejected ({code})")
    return VerifyResult("UNKNOWN")


# ── Slack ──────────────────────────────────────────────────────────────────

def verify_slack_token(token: str) -> VerifyResult:
    """auth.test — Slack's official whoami endpoint."""
    code, body = _request(
        "https://slack.com/api/auth.test",
        {"Authorization": f"Bearer {token}", "Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    if code != 200:
        return VerifyResult("UNKNOWN")
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        return VerifyResult("UNKNOWN")
    if data.get("ok"):
        return VerifyResult(
            "VERIFIED",
            f"team={data.get('team')} user={data.get('user')} url={data.get('url')}",
        )
    err = data.get("error", "unknown_error")
    if err in ("invalid_auth", "token_revoked", "token_expired", "account_inactive"):
        return VerifyResult("UNVERIFIED", err)
    return VerifyResult("UNKNOWN", err)


# ── Stripe ─────────────────────────────────────────────────────────────────

def verify_stripe_key(key: str) -> VerifyResult:
    """GET /v1/charges?limit=1 — minimal read-only call.
    Stripe uses HTTP Basic auth with the secret as the username."""
    import base64
    auth = base64.b64encode(f"{key}:".encode()).decode()
    code, body = _request(
        "https://api.stripe.com/v1/charges?limit=1",
        {"Authorization": f"Basic {auth}"},
    )
    if code == 200:
        return VerifyResult("VERIFIED", "charges:read confirmed")
    if code == 401:
        return VerifyResult("UNVERIFIED", "stripe rejected (invalid key)")
    if code == 403:
        return VerifyResult("VERIFIED", "key valid but lacks charges:read scope")
    return VerifyResult("UNKNOWN")


# ── OpenAI ─────────────────────────────────────────────────────────────────

def verify_openai_key(key: str) -> VerifyResult:
    """GET /v1/models — lightweight, requires only api_key."""
    code, _ = _request("https://api.openai.com/v1/models", {"Authorization": f"Bearer {key}"})
    if code == 200:
        return VerifyResult("VERIFIED", "models:list confirmed")
    if code == 401:
        return VerifyResult("UNVERIFIED", "openai rejected")
    return VerifyResult("UNKNOWN")


# ── Anthropic ──────────────────────────────────────────────────────────────

def verify_anthropic_key(key: str) -> VerifyResult:
    """POST /v1/messages with 1-token request — costs ~$0.0001 if valid.
    We use HEAD on a known endpoint to avoid the cost."""
    # /v1/models requires the key but doesn't bill — preferred check
    code, _ = _request(
        "https://api.anthropic.com/v1/models",
        {"x-api-key": key, "anthropic-version": "2023-06-01"},
    )
    if code == 200:
        return VerifyResult("VERIFIED", "models:list confirmed")
    if code in (401, 403):
        return VerifyResult("UNVERIFIED", f"anthropic rejected ({code})")
    return VerifyResult("UNKNOWN")


# ── Mailgun ────────────────────────────────────────────────────────────────

def verify_mailgun_key(key: str) -> VerifyResult:
    """GET /v3/domains — Basic auth (api:KEY)."""
    import base64
    auth = base64.b64encode(f"api:{key}".encode()).decode()
    code, _ = _request("https://api.mailgun.net/v3/domains", {"Authorization": f"Basic {auth}"})
    if code == 200:
        return VerifyResult("VERIFIED", "mailgun domains accessible")
    if code == 401:
        return VerifyResult("UNVERIFIED", "mailgun rejected")
    return VerifyResult("UNKNOWN")


# ── SendGrid ───────────────────────────────────────────────────────────────

def verify_sendgrid_key(key: str) -> VerifyResult:
    code, _ = _request("https://api.sendgrid.com/v3/scopes", {"Authorization": f"Bearer {key}"})
    if code == 200:
        return VerifyResult("VERIFIED", "sendgrid scopes accessible")
    if code == 401:
        return VerifyResult("UNVERIFIED", "sendgrid rejected")
    return VerifyResult("UNKNOWN")


# ── AWS (SigV4 — most complex) ─────────────────────────────────────────────

def verify_aws_keys(access_key: str, secret_key: str) -> VerifyResult:
    """STS GetCallerIdentity — the canonical AWS whoami.
    Requires both AKIA + secret. We sign a SigV4 GET to sts.amazonaws.com."""
    if not (access_key and secret_key):
        return VerifyResult("UNKNOWN", "secret_access_key not paired with access_key_id")

    region = "us-east-1"
    service = "sts"
    host = "sts.amazonaws.com"
    method = "GET"
    canonical_uri = "/"
    canonical_querystring = "Action=GetCallerIdentity&Version=2011-06-15"
    payload_hash = hashlib.sha256(b"").hexdigest()
    now = datetime.now(timezone.utc)
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    date_stamp = now.strftime("%Y%m%d")

    canonical_headers = f"host:{host}\nx-amz-date:{amz_date}\n"
    signed_headers = "host;x-amz-date"
    canonical_request = "\n".join([
        method, canonical_uri, canonical_querystring,
        canonical_headers, signed_headers, payload_hash,
    ])
    credential_scope = f"{date_stamp}/{region}/{service}/aws4_request"
    string_to_sign = "\n".join([
        "AWS4-HMAC-SHA256", amz_date, credential_scope,
        hashlib.sha256(canonical_request.encode()).hexdigest(),
    ])

    def _sign(key: bytes, msg: str) -> bytes:
        return hmac.new(key, msg.encode(), hashlib.sha256).digest()

    k_date = _sign(("AWS4" + secret_key).encode(), date_stamp)
    k_region = _sign(k_date, region)
    k_service = _sign(k_region, service)
    k_signing = _sign(k_service, "aws4_request")
    signature = hmac.new(k_signing, string_to_sign.encode(), hashlib.sha256).hexdigest()

    authz = (
        f"AWS4-HMAC-SHA256 Credential={access_key}/{credential_scope}, "
        f"SignedHeaders={signed_headers}, Signature={signature}"
    )
    code, body = _request(
        f"https://{host}/?{canonical_querystring}",
        {"Authorization": authz, "x-amz-date": amz_date},
    )
    if code == 200:
        # response is XML — extract Account ID with a quick regex
        import re
        m = re.search(r"<Account>(\d+)</Account>", body)
        acc = m.group(1) if m else "unknown"
        return VerifyResult("VERIFIED", f"aws account={acc}")
    if code in (401, 403):
        return VerifyResult("UNVERIFIED", f"aws rejected ({code})")
    return VerifyResult("UNKNOWN")


# ── Registry ───────────────────────────────────────────────────────────────
# Maps SecretPattern.name → verifier callable. The detector calls into this
# map by name when verification is enabled.

VERIFIERS: dict[str, Callable[[str], VerifyResult]] = {
    "GitHub Personal Access Token": verify_github_token,
    "GitHub App Token": verify_github_token,
    "Slack Bot Token": verify_slack_token,
    "Stripe Live Secret Key": verify_stripe_key,
    "Stripe Restricted Key": verify_stripe_key,
    "OpenAI API Key": verify_openai_key,
    "Anthropic API Key": verify_anthropic_key,
    "Mailgun API Key": verify_mailgun_key,
    "SendGrid API Key": verify_sendgrid_key,
}


def verify(secret_name: str, value: str) -> Optional[VerifyResult]:
    """Run the verifier for a given secret type, if one exists and
    verification is enabled. Returns None if no verifier or disabled."""
    if not _is_enabled():
        return None
    verifier = VERIFIERS.get(secret_name)
    if verifier is None:
        return None
    try:
        return verifier(value)
    except Exception:
        return VerifyResult("UNKNOWN", "verifier raised")
