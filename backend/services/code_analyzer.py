from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
import uuid
from typing import Any, Dict, List, Optional, Tuple

SUPPORTED_LANGUAGES = {"python", "javascript", "java", "php", "go"}

EXTENSION_MAP = {
    ".py": "python",
    ".js": "javascript",
    ".ts": "javascript",
    ".jsx": "javascript",
    ".tsx": "javascript",
    ".java": "java",
    ".php": "php",
    ".go": "go",
}

LANGUAGE_EXTENSIONS = {
    "python": ".py",
    "javascript": ".js",
    "java": ".java",
    "php": ".php",
    "go": ".go",
}

LANGUAGE_KEYWORDS = {
    "python": ["def ", "import ", "print(", "elif ", "self.", "__init__"],
    "javascript": ["function ", "const ", "let ", "=>", "require(", "module.exports"],
    "java": ["public class ", "System.out.println", "import java."],
    "php": ["<?php", "$_", "echo "],
    "go": ["func ", "package main", "fmt.Println", ":="],
}

# Bandit test ID → actionable fix
BANDIT_FIX_MAP: Dict[str, str] = {
    "B101": "Remove assert statements from production code; use explicit conditionals instead.",
    "B102": "Avoid exec() with user-controlled input. Use subprocess with a fixed command list.",
    "B103": "Set file permissions to 0o600 or 0o640, not world-writable (0o777/0o666).",
    "B104": "Bind to a specific interface (e.g. '127.0.0.1') instead of '0.0.0.0' in production.",
    "B105": "Replace hardcoded password with an environment variable: os.environ['SECRET'].",
    "B106": "Replace hardcoded password argument with a value read from env or a secrets manager.",
    "B107": "Replace hardcoded password default with None; require the caller to supply the value.",
    "B108": "Use tempfile.mkstemp() or tempfile.TemporaryFile() instead of predictable paths.",
    "B110": "Log or handle the exception explicitly; bare 'except: pass' hides errors silently.",
    "B201": "Set app.run(debug=False) or use an environment variable to gate debug mode.",
    "B301": "Replace pickle.loads() with a safer format: json.loads() or msgpack.",
    "B302": "Replace marshal.loads() with json.loads() or another safe deserializer.",
    "B303": "Replace MD5/SHA1 with SHA-256 or higher: hashlib.sha256().",
    "B304": "Use a modern cipher (AES-GCM) instead of DES/RC4/Blowfish.",
    "B305": "Replace ECB mode with GCM or CBC with a random IV for each message.",
    "B307": "Replace eval() with ast.literal_eval() for data, or refactor to avoid dynamic execution.",
    "B310": "Validate and allowlist URLs before passing to urllib.urlopen().",
    "B322": "Use input() (Python 3) directly; raw_input no longer exists and this signals Py2 code.",
    "B323": "Pass ssl.create_default_context() and do not set check_hostname=False.",
    "B324": "Replace MD5/SHA1 with SHA-256: hashlib.sha256(data).hexdigest().",
    "B501": "Remove ssl_context=PROTOCOL_SSLv2/SSLv3 and use ssl.PROTOCOL_TLS_CLIENT.",
    "B502": "Remove ssl_version override; let ssl use its default (TLS 1.2+).",
    "B503": "Remove set_ciphers() call or restrict to strong ciphers only.",
    "B504": "Remove ssl_version kwarg and let the library negotiate TLS 1.2+.",
    "B505": "Generate RSA/DSA keys with at least 2048 bits (4096 recommended).",
    "B506": "Disable yaml.load() and use yaml.safe_load() instead.",
    "B602": "Replace shell=True with a list of args: subprocess.run(['cmd', 'arg']).",
    "B603": "Verify the command list contains no user-controlled values before calling subprocess.",
    "B604": "Replace os.system() / popen() shell call with subprocess.run([], shell=False).",
    "B605": "Pass a list to subprocess instead of a shell string to prevent injection.",
    "B607": "Use an absolute path for the executable to prevent PATH hijacking.",
    "B608": "Use parameterized queries: cursor.execute('SELECT * FROM t WHERE id=%s', (id,)).",
    "B610": "Use Django ORM or parameterized raw SQL instead of string-concatenated queries.",
    "B611": "Use Django ORM queryset filters; avoid .extra() with user data.",
    "B701": "Use Jinja2 with autoescape=True or explicitly escape all user-supplied values.",
    "B702": "Enable Mako's h filter or switch to a templating engine with auto-escaping.",
}

# Bandit test ID → CWE
BANDIT_CWE_MAP: Dict[str, str] = {
    "B101": "CWE-617", "B102": "CWE-78",  "B103": "CWE-732", "B104": "CWE-605",
    "B105": "CWE-259", "B106": "CWE-259", "B107": "CWE-259", "B108": "CWE-377",
    "B110": "CWE-391", "B201": "CWE-78",  "B301": "CWE-502", "B302": "CWE-502",
    "B303": "CWE-327", "B304": "CWE-327", "B305": "CWE-327", "B307": "CWE-78",
    "B310": "CWE-601", "B322": "CWE-78",  "B323": "CWE-295", "B324": "CWE-327",
    "B501": "CWE-295", "B502": "CWE-295", "B503": "CWE-295", "B504": "CWE-295",
    "B505": "CWE-326", "B506": "CWE-611", "B602": "CWE-78",  "B603": "CWE-78",
    "B604": "CWE-78",  "B605": "CWE-78",  "B607": "CWE-78",  "B608": "CWE-89",
    "B610": "CWE-89",  "B611": "CWE-89",  "B701": "CWE-134", "B702": "CWE-79",
}


def detect_language(code: str, filename: Optional[str] = None) -> str:
    if filename:
        ext = os.path.splitext(filename)[1].lower()
        if ext in EXTENSION_MAP:
            return EXTENSION_MAP[ext]

    sample = code[:2000]
    scores = {lang: sum(1 for kw in kws if kw in sample) for lang, kws in LANGUAGE_KEYWORDS.items()}
    best = max(scores, key=lambda k: scores[k])
    return best if scores[best] > 0 else "python"


def _bandit_severity(sev: str) -> str:
    return {"HIGH": "high", "MEDIUM": "medium", "LOW": "low"}.get(sev.upper(), "low")


def _semgrep_severity(sev: str) -> str:
    return {"ERROR": "high", "WARNING": "medium", "INFO": "low"}.get(sev.upper(), "low")


def _parse_bandit(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    vulns = []
    for r in data.get("results", []):
        test_id = r.get("test_id", "")
        vulns.append({
            "type": r.get("test_name", "unknown"),
            "severity": _bandit_severity(r.get("issue_severity", "LOW")),
            "line": r.get("line_number"),
            "code_snippet": (r.get("code") or "").strip()[:200],
            "issue": r.get("issue_text", ""),
            "fix": BANDIT_FIX_MAP.get(test_id, r.get("issue_text", "")),
            "cwe": BANDIT_CWE_MAP.get(test_id, ""),
        })
    return vulns


# ── Pattern rules per language ────────────────────────────────────────────────
# Each rule: pattern (regex), type, severity, issue, fix, cwe
# Patterns use re.search on each line; {var} placeholder = any non-whitespace token

_R = re.compile  # alias

PATTERN_RULES: Dict[str, List[Dict]] = {
    "javascript": [
        {
            "re": _R(r"\beval\s*\("),
            "type": "eval_injection",
            "severity": "high",
            "issue": "eval() executes arbitrary code — never pass user-controlled data to it.",
            "fix": "Use JSON.parse() for data, or refactor to remove dynamic execution entirely.",
            "cwe": "CWE-95",
        },
        {
            "re": _R(r"\.innerHTML\s*[+]?=\s*(?!['\"`])"),
            "type": "xss_inner_html",
            "severity": "high",
            "issue": "Assigning a non-literal to innerHTML can introduce reflected or stored XSS.",
            "fix": "Use element.textContent for plain text, or sanitize with DOMPurify before setting innerHTML.",
            "cwe": "CWE-79",
        },
        {
            "re": _R(r"\bdocument\.write\s*\("),
            "type": "xss_document_write",
            "severity": "high",
            "issue": "document.write() with dynamic content enables XSS.",
            "fix": "Use DOM manipulation methods (createElement, appendChild) instead of document.write().",
            "cwe": "CWE-79",
        },
        {
            "re": _R(r"dangerouslySetInnerHTML\s*="),
            "type": "react_xss",
            "severity": "high",
            "issue": "dangerouslySetInnerHTML bypasses React's XSS protection.",
            "fix": "Sanitize the HTML with DOMPurify before passing it to dangerouslySetInnerHTML.",
            "cwe": "CWE-79",
        },
        {
            "re": _R(r"""(?:password|passwd|secret|api_?key|token|auth)\s*[:=]\s*['"][^'"]{4,}['"]""", re.IGNORECASE),
            "type": "hardcoded_secret",
            "severity": "high",
            "issue": "Hardcoded credential or secret found in source code.",
            "fix": "Move secrets to environment variables: process.env.SECRET_NAME.",
            "cwe": "CWE-798",
        },
        {
            "re": _R(r"(?i)(?:SELECT|INSERT|UPDATE|DELETE|FROM\s+\w|WHERE\s+\w)[^\n;]*\+|(?:query|sql)\s*[+]?=\s*.*\+"),
            "type": "sql_injection",
            "severity": "critical",
            "issue": "SQL query built by string concatenation — allows SQL injection.",
            "fix": "Use parameterized queries or a query builder (e.g. knex, sequelize) — never concatenate user input into SQL.",
            "cwe": "CWE-89",
        },
        {
            "re": _R(r"Math\.random\s*\(\s*\)"),
            "type": "weak_random",
            "severity": "medium",
            "issue": "Math.random() is not cryptographically secure — do not use for tokens, IDs, or secrets.",
            "fix": "Use crypto.randomBytes() (Node) or window.crypto.getRandomValues() (browser) instead.",
            "cwe": "CWE-338",
        },
        {
            "re": _R(r"""(?:fetch|axios\.get|axios\.post|http\.get|http\.request)\s*\(\s*['"`]http://"""),
            "type": "insecure_transport",
            "severity": "medium",
            "issue": "Plain HTTP used — data transmitted without encryption.",
            "fix": "Use HTTPS endpoints. Enforce HTTPS in production with HSTS headers.",
            "cwe": "CWE-319",
        },
        {
            "re": _R(r"""(?:exec|execSync|spawn|spawnSync)\s*\(\s*(?:[^'"`\[])"""),
            "type": "command_injection",
            "severity": "critical",
            "issue": "child_process called with a dynamic argument — possible command injection.",
            "fix": "Use execFile() with a fixed command and pass args as an array, never as a concatenated string.",
            "cwe": "CWE-78",
        },
        {
            "re": _R(r"\.outerHTML\s*[+]?=\s*(?!['\"`])"),
            "type": "xss_outer_html",
            "severity": "high",
            "issue": "Assigning to outerHTML with dynamic content enables XSS.",
            "fix": "Use DOM methods (replaceWith, insertAdjacentElement) and sanitize content first.",
            "cwe": "CWE-79",
        },
        {
            "re": _R(r"\bsetTimeout\s*\(\s*(?:[^,\)]*[+`]|[a-zA-Z_$][a-zA-Z0-9_$]*)"),
            "type": "settimeout_injection",
            "severity": "medium",
            "issue": "setTimeout() with a string argument executes arbitrary code like eval().",
            "fix": "Pass a function reference to setTimeout(), never a string.",
            "cwe": "CWE-95",
        },
        {
            "re": _R(r"window\.location(?:\.href)?\s*=\s*(?!['\"]).{0,60}(?:req|request|params|query|search|hash)", re.IGNORECASE),
            "type": "open_redirect",
            "severity": "medium",
            "issue": "Redirect target derived from user-controlled input — open redirect vulnerability.",
            "fix": "Validate redirect URLs against an allowlist of trusted origins before redirecting.",
            "cwe": "CWE-601",
        },
        {
            "re": _R(r"require\s*\(\s*(?:req|request|params|body|query|user)", re.IGNORECASE),
            "type": "dynamic_require",
            "severity": "high",
            "issue": "require() called with user-controlled input allows arbitrary module loading.",
            "fix": "Never pass user input to require(). Use a lookup map of allowed module names.",
            "cwe": "CWE-829",
        },
        {
            "re": _R(r"rejectUnauthorized\s*:\s*false"),
            "type": "tls_verification_disabled",
            "severity": "high",
            "issue": "TLS certificate verification disabled — vulnerable to man-in-the-middle attacks.",
            "fix": "Remove rejectUnauthorized: false. Use a proper CA bundle or NODE_EXTRA_CA_CERTS for custom certs.",
            "cwe": "CWE-295",
        },
        {
            "re": _R(r"\.cookie\s*=.*(?:(?!HttpOnly)(?!Secure))", re.IGNORECASE),
            "type": "insecure_cookie",
            "severity": "medium",
            "issue": "Cookie set without HttpOnly or Secure flags — exposed to XSS and network sniffing.",
            "fix": "Add HttpOnly and Secure flags: document.cookie = 'name=value; HttpOnly; Secure; SameSite=Strict'.",
            "cwe": "CWE-614",
        },
    ],
    "java": [
        {
            "re": _R(r"Runtime\.getRuntime\(\)\.exec\s*\("),
            "type": "command_injection",
            "severity": "critical",
            "issue": "Runtime.exec() with dynamic input allows OS command injection.",
            "fix": "Use ProcessBuilder with a String[] args array, never a single concatenated string.",
            "cwe": "CWE-78",
        },
        {
            "re": _R(r'["\s+]SELECT|INSERT|UPDATE|DELETE[^;]*"\s*\+', re.IGNORECASE),
            "type": "sql_injection",
            "severity": "critical",
            "issue": "SQL built via string concatenation — SQL injection risk.",
            "fix": "Use PreparedStatement with ? placeholders instead of string concatenation.",
            "cwe": "CWE-89",
        },
        {
            "re": _R(r"new\s+ObjectInputStream\s*\("),
            "type": "insecure_deserialization",
            "severity": "critical",
            "issue": "Java deserialization of untrusted data can lead to remote code execution.",
            "fix": "Use a serialization filter (ObjectInputFilter), avoid deserializing untrusted data, or use JSON.",
            "cwe": "CWE-502",
        },
        {
            "re": _R(r"""(?:password|secret|apikey|api_key)\s*=\s*["'][^"']{4,}["']""", re.IGNORECASE),
            "type": "hardcoded_secret",
            "severity": "high",
            "issue": "Hardcoded credential in source code.",
            "fix": "Load secrets from environment variables or a secrets manager (e.g. AWS Secrets Manager).",
            "cwe": "CWE-798",
        },
        {
            "re": _R(r"MessageDigest\.getInstance\s*\(\s*[\"'](?:MD5|SHA-1)[\"']", re.IGNORECASE),
            "type": "weak_hash",
            "severity": "high",
            "issue": "MD5/SHA-1 are cryptographically broken — do not use for security purposes.",
            "fix": "Use SHA-256 or SHA-3: MessageDigest.getInstance(\"SHA-256\").",
            "cwe": "CWE-327",
        },
        {
            "re": _R(r"new\s+Random\s*\("),
            "type": "weak_random",
            "severity": "medium",
            "issue": "java.util.Random is not cryptographically secure.",
            "fix": "Use java.security.SecureRandom instead of java.util.Random.",
            "cwe": "CWE-338",
        },
        {
            "re": _R(r"setHostnameVerifier\s*\(\s*(?:ALLOW_ALL|allHosts)", re.IGNORECASE),
            "type": "tls_hostname_disabled",
            "severity": "high",
            "issue": "Hostname verification disabled — vulnerable to MITM attacks.",
            "fix": "Use the default hostname verifier or implement proper certificate pinning.",
            "cwe": "CWE-295",
        },
        {
            "re": _R(r"\.printStackTrace\s*\("),
            "type": "info_leak_stack_trace",
            "severity": "low",
            "issue": "Stack trace printed to output may expose internal paths and class names.",
            "fix": "Log the exception with a logger at ERROR level; never send stack traces to end users.",
            "cwe": "CWE-209",
        },
    ],
    "php": [
        {
            "re": _R(r"\beval\s*\("),
            "type": "eval_injection",
            "severity": "critical",
            "issue": "eval() executes PHP code — extremely dangerous with user input.",
            "fix": "Remove eval(). Restructure code to avoid dynamic PHP execution.",
            "cwe": "CWE-95",
        },
        {
            "re": _R(r"\$_(GET|POST|REQUEST|COOKIE|SERVER)\["),
            "type": "unvalidated_input",
            "severity": "medium",
            "issue": "Superglobal used directly without validation or sanitization.",
            "fix": "Validate and sanitize all superglobal values: filter_input(INPUT_GET, 'key', FILTER_SANITIZE_STRING).",
            "cwe": "CWE-20",
        },
        {
            "re": _R(r"mysql_query\s*\(|mysqli_query\s*\([^,]+,\s*['\"]?\s*(?:SELECT|INSERT|UPDATE|DELETE)[^'\"]*\$", re.IGNORECASE),
            "type": "sql_injection",
            "severity": "critical",
            "issue": "SQL query built with unsanitized user input.",
            "fix": "Use PDO with prepared statements: $stmt = $pdo->prepare('SELECT * FROM t WHERE id = ?'); $stmt->execute([$id]);",
            "cwe": "CWE-89",
        },
        {
            "re": _R(r"\becho\s+\$_(GET|POST|REQUEST|COOKIE)"),
            "type": "reflected_xss",
            "severity": "high",
            "issue": "User input echoed directly to HTML — reflected XSS.",
            "fix": "Escape output: echo htmlspecialchars($_GET['x'], ENT_QUOTES, 'UTF-8');",
            "cwe": "CWE-79",
        },
        {
            "re": _R(r"(?:system|exec|shell_exec|passthru|popen)\s*\("),
            "type": "command_injection",
            "severity": "critical",
            "issue": "OS command execution with potentially user-controlled input.",
            "fix": "Use escapeshellarg() on all arguments; prefer PHP built-in functions over shell commands.",
            "cwe": "CWE-78",
        },
        {
            "re": _R(r"md5\s*\(|sha1\s*\("),
            "type": "weak_hash",
            "severity": "high",
            "issue": "MD5/SHA1 are broken — do not use for passwords or security-sensitive hashing.",
            "fix": "For passwords use password_hash($pw, PASSWORD_BCRYPT). For data integrity use hash('sha256', $data).",
            "cwe": "CWE-327",
        },
        {
            "re": _R(r"""(?:password|passwd|secret|api_?key)\s*=\s*['"][^'"]{4,}['"]""", re.IGNORECASE),
            "type": "hardcoded_secret",
            "severity": "high",
            "issue": "Hardcoded credential in source code.",
            "fix": "Read secrets from environment: getenv('DB_PASSWORD') or a secrets manager.",
            "cwe": "CWE-798",
        },
    ],
    "go": [
        {
            "re": _R(r"exec\.Command\s*\([^)]*\+"),
            "type": "command_injection",
            "severity": "critical",
            "issue": "exec.Command called with a concatenated string — command injection risk.",
            "fix": "Pass each argument separately as a string literal: exec.Command(\"cmd\", arg1, arg2).",
            "cwe": "CWE-78",
        },
        {
            "re": _R(r'fmt\.Sprintf\s*\(\s*["\'](?:SELECT|INSERT|UPDATE|DELETE)', re.IGNORECASE),
            "type": "sql_injection",
            "severity": "critical",
            "issue": "SQL query assembled with fmt.Sprintf — SQL injection risk.",
            "fix": "Use parameterized queries: db.Query(\"SELECT * FROM t WHERE id = $1\", id).",
            "cwe": "CWE-89",
        },
        {
            "re": _R(r"""(?:password|secret|apiKey|api_key)\s*:?=\s*["'][^"']{4,}["']""", re.IGNORECASE),
            "type": "hardcoded_secret",
            "severity": "high",
            "issue": "Hardcoded credential in source code.",
            "fix": "Use os.Getenv(\"SECRET\") or a secrets manager instead of hardcoded values.",
            "cwe": "CWE-798",
        },
        {
            "re": _R(r"InsecureSkipVerify\s*:\s*true"),
            "type": "tls_verification_disabled",
            "severity": "high",
            "issue": "TLS certificate verification disabled — MITM attacks possible.",
            "fix": "Remove InsecureSkipVerify: true. Load trusted CA certs with tls.Config{RootCAs: pool}.",
            "cwe": "CWE-295",
        },
        {
            "re": _R(r"math/rand"),
            "type": "weak_random",
            "severity": "medium",
            "issue": "math/rand is not cryptographically secure.",
            "fix": "Use crypto/rand for security-sensitive random values: rand.Read(b).",
            "cwe": "CWE-338",
        },
        {
            "re": _R(r"md5\.New\(\)|sha1\.New\(\)"),
            "type": "weak_hash",
            "severity": "high",
            "issue": "MD5/SHA1 are cryptographically broken.",
            "fix": "Use sha256.New() or sha512.New() from crypto/sha256 or crypto/sha512.",
            "cwe": "CWE-327",
        },
        {
            "re": _R(r"html/template"),
            "type": "template_xss_check",
            "severity": "low",
            "issue": "Ensure template.HTML() casts are not used with user-supplied data.",
            "fix": "Never cast user input to template.HTML, template.JS, or template.URL — these bypass auto-escaping.",
            "cwe": "CWE-79",
        },
    ],
}


def run_pattern_analysis(code: str, language: str) -> List[Dict[str, Any]]:
    rules = PATTERN_RULES.get(language, [])
    if not rules:
        return []

    lines = code.splitlines()
    vulns: List[Dict[str, Any]] = []
    seen: set = set()  # (type, line_no) dedup

    for lineno, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith(("//", "#", "*", "/*")):
            continue
        for rule in rules:
            if rule["re"].search(line):
                key = (rule["type"], lineno)
                if key in seen:
                    continue
                seen.add(key)
                vulns.append({
                    "type":         rule["type"],
                    "severity":     rule["severity"],
                    "line":         lineno,
                    "code_snippet": line.strip()[:200],
                    "issue":        rule["issue"],
                    "fix":          rule["fix"],
                    "cwe":          rule["cwe"],
                })

    return vulns


def _run_subprocess(cmd: List[str], timeout: int) -> Tuple[str, Optional[str]]:
    try:
        env = os.environ.copy()
        env["PYTHONIOENCODING"] = "utf-8"
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                              env=env, encoding="utf-8", errors="replace")
        return proc.stdout.strip(), None
    except FileNotFoundError:
        return "", f"Tool not found: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return "", f"Analysis timed out after {timeout}s"


# Absolute path to the ESLint toolchain bundled with alphaweb
_JS_TOOLS_DIR = os.path.join(os.path.dirname(__file__), "..", "tools", "js")
_JS_TOOLS_DIR = os.path.normpath(_JS_TOOLS_DIR)
_ESLINT_BIN   = os.path.join(_JS_TOOLS_DIR, "node_modules", ".bin",
                              "eslint.cmd" if os.name == "nt" else "eslint")
_ESLINT_CFG   = os.path.join(_JS_TOOLS_DIR, ".eslintrc.json")

# ESLint severity: 1 = warn, 2 = error
_ESLINT_SEV = {2: "high", 1: "medium"}

# Map ESLint rule IDs → (severity override, issue text, fix text, cwe)
_ESLINT_RULE_META: Dict[str, Tuple[str, str, str, str]] = {
    "no-eval":                               ("high",     "eval() executes arbitrary code.",                                                                "Replace eval() with JSON.parse() for data or refactor to avoid dynamic execution.",       "CWE-95"),
    "security/detect-eval-with-expression":  ("high",     "eval() called with a non-literal expression — code injection risk.",                             "Replace eval() with JSON.parse() for data or refactor to avoid dynamic execution.",       "CWE-95"),
    "no-unsanitized/property":               ("high",     "Unsanitized value assigned to an HTML sink — XSS risk.",                                         "Use textContent for plain text, or sanitize with DOMPurify before setting innerHTML.",     "CWE-79"),
    "no-unsanitized/method":                 ("high",     "Unsanitized value passed to an HTML method — XSS risk.",                                         "Sanitize user data with DOMPurify or use safe DOM methods instead.",                      "CWE-79"),
    "security/detect-child-process":         ("critical", "child_process used — verify no user-controlled input reaches exec/spawn.",                       "Use execFile() with a fixed binary and pass arguments as an array, never as a string.",   "CWE-78"),
    "security/detect-non-literal-require":   ("high",     "require() called with a non-literal — allows arbitrary module loading.",                         "Use a static string literal in require(). Map user input to an allowlist of module names.","CWE-829"),
    "security/detect-object-injection":      ("medium",   "Property accessed via a user-controlled key — potential object injection.",                      "Validate the key against an explicit allowlist before using it as a property accessor.",   "CWE-915"),
    "security/detect-non-literal-regexp":    ("medium",   "RegExp constructed from a non-literal — potential ReDoS.",                                       "Use a literal regex or validate/escape the pattern with safe-regex before compiling it.",  "CWE-400"),
    "security/detect-unsafe-regex":          ("medium",   "Regex pattern is vulnerable to ReDoS (catastrophic backtracking).",                              "Simplify the regex or use the safe-regex package to validate it is bounded.",             "CWE-400"),
    "security/detect-possible-timing-attacks":("medium",  "String comparison may be vulnerable to timing attacks.",                                         "Use crypto.timingSafeEqual() for security-sensitive comparisons (e.g. HMAC verification).","CWE-208"),
    "security/detect-pseudoRandomBytes":     ("medium",   "crypto.pseudoRandomBytes() is deprecated and not cryptographically strong.",                     "Use crypto.randomBytes() instead.",                                                       "CWE-338"),
    "security/detect-disable-mustache-escape":("high",    "Mustache HTML escaping disabled in template — XSS risk.",                                        "Remove {{{triple-stache}}} or set escaping: true in your template options.",              "CWE-79"),
    "security/detect-new-buffer":            ("medium",   "new Buffer() is deprecated and may expose uninitialized memory.",                                "Use Buffer.alloc(n) for zeroed buffers or Buffer.from(data) for existing data.",          "CWE-119"),
    "security/detect-no-csrf-before-method-override":("high","express methodOverride() used before CSRF protection — CSRF bypass possible.",                "Mount CSRF middleware before methodOverride() in the Express middleware stack.",           "CWE-352"),
    "security/detect-non-literal-fs-filename":("medium",  "fs function called with a non-literal filename — path traversal risk.",                          "Validate and sanitize file paths: use path.basename() and restrict to an allowed directory.","CWE-22"),
    "security/detect-bidi-characters":       ("high",     "Bidirectional Unicode control characters found — possible Trojan-source attack.",                "Remove all bidi control characters (U+202A–U+202E, U+2066–U+2069, U+200F, etc.).",      "CWE-116"),
    "security/detect-buffer-noassert":       ("low",      "Buffer read/write called with noAssert=true — skips bounds checking.",                           "Remove the noAssert flag to enable bounds checking.",                                     "CWE-119"),
}


def _parse_eslint(data: List[Dict[str, Any]], code: str) -> List[Dict[str, Any]]:
    lines = code.splitlines()
    vulns = []
    for file_result in data:
        for msg in file_result.get("messages", []):
            rule_id   = msg.get("ruleId") or "unknown"
            lineno    = msg.get("line", 0)
            meta      = _ESLINT_RULE_META.get(rule_id)
            severity  = meta[0] if meta else _ESLINT_SEV.get(msg.get("severity", 1), "low")
            issue     = meta[1] if meta else msg.get("message", "")
            fix       = meta[2] if meta else ""
            cwe       = meta[3] if meta else ""
            snippet   = lines[lineno - 1].strip()[:200] if 0 < lineno <= len(lines) else ""
            vulns.append({
                "type":         rule_id.replace("/", "_").replace("-", "_"),
                "severity":     severity,
                "line":         lineno,
                "code_snippet": snippet,
                "issue":        issue,
                "fix":          fix,
                "cwe":          cwe,
            })
    return vulns


def run_eslint(code: str, timeout: int = 30) -> Tuple[List[Dict], Optional[str]]:
    if not os.path.isfile(_ESLINT_BIN):
        return [], f"ESLint not found at {_ESLINT_BIN}"

    with tempfile.NamedTemporaryFile(mode="w", suffix=".js", delete=False, encoding="utf-8") as f:
        f.write(code)
        tmp = f.name
    try:
        env = os.environ.copy()
        env["PYTHONIOENCODING"] = "utf-8"
        proc = subprocess.run(
            [_ESLINT_BIN, "--no-eslintrc", "-c", _ESLINT_CFG, "--format", "json", tmp],
            capture_output=True, text=True, timeout=timeout,
            env=env, encoding="utf-8", errors="replace",
        )
        # eslint exits 1 when issues found — that's normal, not an error
        out = proc.stdout.strip()
        if not out:
            return [], None
        data = json.loads(out)
        return _parse_eslint(data, code), None
    except json.JSONDecodeError as e:
        return [], f"Failed to parse ESLint output: {e}"
    except subprocess.TimeoutExpired:
        return [], "ESLint timed out"
    finally:
        os.unlink(tmp)


def run_bandit(code: str, timeout: int = 30) -> Tuple[List[Dict], Optional[str]]:
    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False, encoding="utf-8") as f:
        f.write(code)
        tmp = f.name
    try:
        out, err = _run_subprocess(["bandit", "-f", "json", "-q", tmp], timeout)
        if err:
            return [], err
        if not out:
            return [], None
        data = json.loads(out)
        return _parse_bandit(data), None
    except json.JSONDecodeError as e:
        return [], f"Failed to parse bandit output: {e}"
    finally:
        os.unlink(tmp)


def analyze(code: str, language: Optional[str], filename: Optional[str]) -> Dict[str, Any]:
    if len(code.encode("utf-8")) > 10 * 1024 * 1024:
        raise ValueError("Code exceeds 10MB limit")

    lang = language.lower().strip() if language else detect_language(code, filename)

    if lang not in SUPPORTED_LANGUAGES:
        raise ValueError(
            f"Unsupported language: {lang}. Supported: {', '.join(sorted(SUPPORTED_LANGUAGES))}"
        )

    if lang == "python":
        vulns, error = run_bandit(code)
        pattern_vulns = run_pattern_analysis(code, lang)
        seen = {(v["type"], v["line"]) for v in vulns}
        vulns += [v for v in pattern_vulns if (v["type"], v["line"]) not in seen]
        error = None

    elif lang == "javascript":
        vulns, eslint_err = run_eslint(code)
        if eslint_err:
            vulns = run_pattern_analysis(code, lang)
        else:
            # Deduplicate ESLint findings first (same line + same CWE → keep first)
            seen_lc: set = set()
            deduped: List[Dict] = []
            for v in vulns:
                key = (v["line"], v["cwe"])
                if key not in seen_lc:
                    seen_lc.add(key)
                    deduped.append(v)
            vulns = deduped
            # Add pattern findings only for lines/CWEs not already covered by ESLint
            pattern_vulns = run_pattern_analysis(code, lang)
            for v in pattern_vulns:
                key = (v["line"], v["cwe"])
                if key not in seen_lc:
                    seen_lc.add(key)
                    vulns.append(v)
        error = None

    else:
        # Java → PMD (not installed), PHP → PHPStan (not installed), Go → gosec (not installed)
        # Pattern analysis is the reliable fallback for all three
        vulns = run_pattern_analysis(code, lang)
        error = None

    counts: Dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for v in vulns:
        sev = v.get("severity", "low").lower()
        if sev in counts:
            counts[sev] += 1

    return {
        "analysis_id": str(uuid.uuid4()),
        "language": lang,
        "total_vulnerabilities": len(vulns),
        "critical": counts["critical"],
        "high": counts["high"],
        "medium": counts["medium"],
        "low": counts["low"],
        "vulnerabilities": vulns,
        "tool_error": error,
    }
