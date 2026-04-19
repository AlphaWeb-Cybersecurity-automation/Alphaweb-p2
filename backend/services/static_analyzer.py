"""
static_analyzer.py

Rule-based static analysis for:
  - Source code (Python via Bandit, JS via ESLint + patterns, Java/PHP/Go via patterns, Semgrep when available)
  - Android APK files (manifest permissions + security flags, secret detection, smali patterns)
  - ZIP archives (analyzes all contained source code files)

No ML/LLM required — pure static analysis.
"""

from __future__ import annotations

import io
import json
import os
import re
import subprocess
import tempfile
import uuid
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from services.code_analyzer import (
    EXTENSION_MAP,
    SUPPORTED_LANGUAGES,
    analyze as _base_code_analyze,
)

# ── Semgrep ────────────────────────────────────────────────────────────────────

_SEMGREP_LANG_MAP = {
    "python":     "python",
    "javascript": "javascript",
    "java":       "java",
    "php":        "php",
    "go":         "go",
}

_SEMGREP_EXT_MAP = {
    "python": ".py", "javascript": ".js", "java": ".java", "php": ".php", "go": ".go",
}

_SEMGREP_SEV = {"ERROR": "high", "WARNING": "medium", "INFO": "low", "CRITICAL": "critical"}


def _semgrep_available() -> bool:
    try:
        subprocess.run(["semgrep", "--version"], capture_output=True, timeout=5)
        return True
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return False


def _run_semgrep(code: str, language: str, timeout: int = 60) -> Tuple[List[Dict], Optional[str]]:
    sg_lang = _SEMGREP_LANG_MAP.get(language)
    if not sg_lang:
        return [], f"Semgrep: unsupported language {language}"
    if not _semgrep_available():
        return [], "Semgrep not installed"

    suffix = _SEMGREP_EXT_MAP.get(language, ".txt")
    with tempfile.NamedTemporaryFile(mode="w", suffix=suffix, delete=False, encoding="utf-8") as f:
        f.write(code)
        tmp = f.name

    try:
        env = os.environ.copy()
        env["PYTHONIOENCODING"] = "utf-8"
        proc = subprocess.run(
            ["semgrep", "--json", "--quiet", "--config", "p/security-audit", "--lang", sg_lang, tmp],
            capture_output=True, text=True, timeout=timeout, env=env, encoding="utf-8", errors="replace",
        )
        out = proc.stdout.strip()
        if not out:
            return [], None
        data = json.loads(out)
        results = []
        for r in data.get("results", []):
            extra = r.get("extra", {})
            sev = _SEMGREP_SEV.get(extra.get("severity", "WARNING").upper(), "medium")
            meta = extra.get("metadata", {})
            cwes = meta.get("cwe", [])
            cwe = (cwes[0] if cwes else "") if isinstance(cwes, list) else str(cwes)
            results.append({
                "type":         r.get("check_id", "semgrep").split(".")[-1].replace("-", "_"),
                "severity":     sev,
                "line":         r.get("start", {}).get("line"),
                "code_snippet": extra.get("lines", "").strip()[:200],
                "issue":        extra.get("message", ""),
                "fix":          extra.get("fix", ""),
                "cwe":          cwe,
                "tool":         "semgrep",
                "rule_id":      r.get("check_id", ""),
            })
        return results, None
    except (FileNotFoundError, json.JSONDecodeError) as e:
        return [], f"Semgrep error: {e}"
    except subprocess.TimeoutExpired:
        return [], "Semgrep timed out"
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass


# ── APK: Dangerous permission registry ────────────────────────────────────────

# (severity, human description)
DANGEROUS_PERMISSIONS: Dict[str, Tuple[str, str]] = {
    "READ_CONTACTS":            ("high",     "Reads user's contact list — privacy risk"),
    "WRITE_CONTACTS":           ("high",     "Modifies contact list"),
    "READ_CALL_LOG":            ("high",     "Reads call history — privacy risk"),
    "WRITE_CALL_LOG":           ("high",     "Modifies call history"),
    "READ_SMS":                 ("high",     "Reads SMS messages — can intercept 2FA codes"),
    "RECEIVE_SMS":              ("high",     "Intercepts incoming SMS — can capture 2FA codes"),
    "SEND_SMS":                 ("high",     "Sends SMS silently — can incur costs"),
    "READ_PHONE_STATE":         ("medium",   "Accesses device identifiers (IMEI, IMSI)"),
    "CALL_PHONE":               ("high",     "Makes phone calls without user interaction"),
    "ACCESS_FINE_LOCATION":     ("high",     "Precise GPS location — major privacy concern"),
    "ACCESS_COARSE_LOCATION":   ("medium",   "Approximate location via cell towers/WiFi"),
    "ACCESS_BACKGROUND_LOCATION": ("high",  "Background location access — potential stalkerware"),
    "RECORD_AUDIO":             ("high",     "Records microphone audio — severe privacy risk"),
    "CAMERA":                   ("high",     "Camera access — severe privacy risk"),
    "READ_EXTERNAL_STORAGE":    ("medium",   "Reads all files on external storage"),
    "WRITE_EXTERNAL_STORAGE":   ("medium",   "Writes to all files on external storage"),
    "MANAGE_EXTERNAL_STORAGE":  ("high",     "Unrestricted storage access — requires justification"),
    "PROCESS_OUTGOING_CALLS":   ("high",     "Intercepts and redirects outgoing calls"),
    "GET_ACCOUNTS":             ("medium",   "Lists all accounts on device"),
    "BIND_DEVICE_ADMIN":        ("critical", "Device administrator — can lock/wipe device"),
    "INSTALL_PACKAGES":         ("critical", "Can silently install other applications"),
    "DELETE_PACKAGES":          ("high",     "Can uninstall applications"),
    "REQUEST_INSTALL_PACKAGES": ("high",     "Can request installation of other APKs"),
    "SYSTEM_ALERT_WINDOW":      ("high",     "Overlay over other apps — phishing/clickjacking risk"),
    "ACCESSIBILITY_SERVICE":    ("critical", "Can read screen and perform actions — spyware risk"),
    "PACKAGE_USAGE_STATS":      ("medium",   "Monitors which apps are in use"),
    "BLUETOOTH_ADMIN":          ("medium",   "Scans for and connects to Bluetooth devices"),
    "BROADCAST_SMS":            ("high",     "Broadcasts SMS content to other apps"),
    "MOUNT_UNMOUNT_FILESYSTEMS":("high",     "Mount/unmount file systems"),
    "CHANGE_NETWORK_STATE":     ("medium",   "Can change network connectivity"),
    "CHANGE_WIFI_STATE":        ("medium",   "Can enable/disable WiFi"),
    "NFC":                      ("medium",   "NFC communication"),
    "USE_BIOMETRIC":            ("medium",   "Accesses biometric sensor"),
    "USE_FINGERPRINT":          ("medium",   "Accesses fingerprint sensor"),
}

# ── APK: Manifest security flag checks ────────────────────────────────────────

# (text_to_find, type, severity, issue, fix, cwe)
MANIFEST_FLAGS: List[Tuple[str, str, str, str, str, str]] = [
    (
        "android:debuggable",
        "debuggable_build", "critical",
        "android:debuggable=true allows runtime debugging and memory inspection via ADB on any device.",
        "Remove android:debuggable from the manifest. Release builds are non-debuggable by default.",
        "CWE-489",
    ),
    (
        'android:allowBackup="true"',
        "backup_enabled", "medium",
        "android:allowBackup=true allows ADB backup of app data without root on older Android versions.",
        'Set android:allowBackup="false" or implement a custom BackupAgent with proper data filtering.',
        "CWE-312",
    ),
    (
        'android:usesCleartextTraffic="true"',
        "cleartext_traffic_allowed", "high",
        "Cleartext HTTP traffic explicitly permitted — sensitive data can be transmitted unencrypted.",
        'Set android:usesCleartextTraffic="false" and use HTTPS for all endpoints.',
        "CWE-319",
    ),
    (
        "android:testOnly",
        "test_only_build", "high",
        "android:testOnly=true marks the app as a test artifact — should never be distributed to users.",
        "Remove android:testOnly from production builds.",
        "CWE-489",
    ),
    (
        "android:sharedUserId",
        "shared_user_id", "medium",
        "sharedUserId blurs trust boundaries between apps sharing the same UID.",
        "Avoid sharedUserId; deprecated in API 29+.",
        "CWE-264",
    ),
]

# ── APK: Secret detection patterns ────────────────────────────────────────────

APK_SECRET_PATTERNS: List[Tuple[re.Pattern, str, str, str, str, str]] = [
    (
        re.compile(r'(?:api[_\-]?key|apikey)\s*[=:]\s*["\']([A-Za-z0-9_\-]{16,})["\']', re.IGNORECASE),
        "hardcoded_api_key", "high",
        "Hardcoded API key found in APK resources.",
        "Store API keys server-side; use Android Keystore for device-bound secrets.",
        "CWE-798",
    ),
    (
        re.compile(r'(?:password|passwd|secret|token|auth[_\-]?token)\s*[=:]\s*["\']([^"\']{6,})["\']', re.IGNORECASE),
        "hardcoded_secret", "high",
        "Hardcoded credential or secret found.",
        "Use Android EncryptedSharedPreferences or the Android Keystore; never hardcode secrets.",
        "CWE-798",
    ),
    (
        re.compile(r'AIza[A-Za-z0-9_\-]{35}'),
        "google_api_key", "high",
        "Google API key embedded in APK.",
        "Restrict key in Google Cloud Console; route sensitive API calls through a backend proxy.",
        "CWE-798",
    ),
    (
        re.compile(r'AAAA[A-Za-z0-9_\-]{7}:[A-Za-z0-9_\-]{140}'),
        "firebase_server_key", "critical",
        "Firebase server key exposed — allows sending push notifications to all app users.",
        "Rotate the key immediately. Server keys must never appear in client APKs.",
        "CWE-798",
    ),
    (
        re.compile(r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----'),
        "private_key_embedded", "critical",
        "Private key embedded in APK.",
        "Remove all private keys from the APK; use Android Keystore for cryptographic material.",
        "CWE-321",
    ),
    (
        re.compile(r'jdbc:[a-z]+://[^\s"\'<>]{10,}', re.IGNORECASE),
        "database_url_embedded", "high",
        "Database connection string found in APK — may contain credentials.",
        "Never embed database URLs in mobile apps. Proxy all DB access through a backend API.",
        "CWE-798",
    ),
    (
        re.compile(r'https?://(?:localhost|127\.0\.0\.1|10\.\d+\.\d+\.\d+|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)', re.IGNORECASE),
        "internal_url_exposed", "medium",
        "Internal or development URL embedded in APK.",
        "Remove all internal/development URLs before release builds.",
        "CWE-200",
    ),
    (
        re.compile(r'http://(?!schemas\.android\.com|www\.w3\.org|xmlpull\.org)[a-zA-Z0-9.\-_/]+', re.IGNORECASE),
        "plaintext_http_endpoint", "medium",
        "Plain HTTP endpoint used — data transmitted without encryption.",
        "Migrate all HTTP endpoints to HTTPS.",
        "CWE-319",
    ),
]

# ── APK: Smali dangerous-API patterns ─────────────────────────────────────────

SMALI_PATTERNS: List[Tuple[re.Pattern, str, str, str, str, str]] = [
    (
        re.compile(r'invoke-virtual.*Ljava/lang/Runtime;->exec\(', re.IGNORECASE),
        "runtime_exec", "critical",
        "Runtime.exec() used — OS command execution from the app.",
        "Avoid exec() in Android apps; validate all inputs and prefer built-in APIs.",
        "CWE-78",
    ),
    (
        re.compile(r'Landroid/webkit/WebView;->addJavascriptInterface\(', re.IGNORECASE),
        "webview_javascript_interface", "high",
        "addJavascriptInterface() exposes Java objects to JavaScript; XSS in the WebView can lead to RCE on Android < 4.2.",
        "Restrict to targetSdkVersion >= 17; annotate exposed methods with @JavascriptInterface; only expose trusted code.",
        "CWE-749",
    ),
    (
        re.compile(r'Landroid/telephony/SmsManager;->sendTextMessage\(', re.IGNORECASE),
        "silent_sms_sending", "high",
        "SMS sent programmatically without visible user confirmation.",
        "Always show a confirmation dialog before sending SMS; validate all SMS content.",
        "CWE-862",
    ),
    (
        re.compile(r'Landroid/telephony/TelephonyManager;->(?:getDeviceId|getImei|getMeid)\(', re.IGNORECASE),
        "device_id_collection", "medium",
        "Hardware device identifier (IMEI/MEID) collected.",
        "Use privacy-safe alternatives: Advertising ID or a UUID stored in EncryptedSharedPreferences.",
        "CWE-359",
    ),
    (
        re.compile(r'Landroid/content/Context;->openFileOutput\([^)]*MODE_WORLD_READABLE', re.IGNORECASE),
        "world_readable_file", "high",
        "File created with MODE_WORLD_READABLE — readable by any app on the device.",
        "Use MODE_PRIVATE for all app-internal files.",
        "CWE-732",
    ),
    (
        re.compile(r'Ljavax/crypto/Cipher;->getInstance.*(?:DES|RC4|Blowfish|ECB)', re.IGNORECASE),
        "weak_cipher", "high",
        "Weak or broken cipher algorithm used (DES/RC4/Blowfish/ECB).",
        "Use AES-GCM (128-bit or 256-bit key) with a fresh random IV for each encryption.",
        "CWE-327",
    ),
    (
        re.compile(r'Ljava/security/MessageDigest;->getInstance.*(?:MD5|SHA-1)', re.IGNORECASE),
        "weak_hash", "high",
        "MD5 or SHA-1 used — cryptographically broken.",
        "Use SHA-256 or SHA-3: MessageDigest.getInstance(\"SHA-256\").",
        "CWE-327",
    ),
    (
        re.compile(r'X509TrustManager|SSLCertificateSocketFactory|ALLOW_ALL_HOSTNAME_VERIFIER', re.IGNORECASE),
        "ssl_bypass_risk", "high",
        "Custom SSL/TLS implementation detected — may disable certificate validation.",
        "Use the default Android SSL stack; implement certificate pinning via network_security_config.xml.",
        "CWE-295",
    ),
    (
        re.compile(r'Landroid/content/SharedPreferences[^;]*(?:password|secret|token|key)', re.IGNORECASE),
        "sensitive_in_shared_prefs", "high",
        "Sensitive data potentially stored in unencrypted SharedPreferences.",
        "Use EncryptedSharedPreferences (Jetpack Security library) for any sensitive values.",
        "CWE-312",
    ),
    (
        re.compile(r'invoke-virtual.*Ljava/lang/reflect/Method;->invoke\(', re.IGNORECASE),
        "reflection_usage", "low",
        "Java reflection used — may hide actual API calls from static analyzers.",
        "Document all reflective calls; prefer direct method invocation where possible.",
        "CWE-470",
    ),
]


# ── Utilities ──────────────────────────────────────────────────────────────────

def _extract_ascii_strings(data: bytes, min_len: int = 6) -> List[str]:
    return [m.group().decode("ascii", errors="ignore") for m in re.finditer(rb"[ -~]{%d,}" % min_len, data)]


def _find_permissions_binary(data: bytes) -> List[str]:
    """Extract Android permission names from a binary AndroidManifest.xml."""
    found: List[str] = []

    # ASCII: "android.permission.XXXX"
    for m in re.finditer(rb"android\.permission\.([A-Z_]{3,50})", data):
        found.append(m.group(1).decode("ascii"))

    # UTF-16LE: same pattern with null bytes between chars
    utf16_marker = "android.permission.".encode("utf-16-le")
    pos = 0
    while True:
        idx = data.find(utf16_marker, pos)
        if idx == -1:
            break
        # Read following UTF-16LE characters
        chars: List[str] = []
        i = idx + len(utf16_marker)
        while i + 1 < len(data):
            lo, hi = data[i], data[i + 1]
            if hi == 0 and (chr(lo).isalpha() or chr(lo) == "_"):
                chars.append(chr(lo))
                i += 2
            else:
                break
        if chars:
            found.append("".join(chars))
        pos = idx + 1

    return list(set(found))


def _find_flags_binary(data: bytes, flag_text: str) -> bool:
    """Check whether a manifest flag string is present in ASCII or UTF-16LE."""
    if flag_text.encode("ascii") in data:
        return True
    if flag_text.encode("utf-16-le") in data:
        return True
    return False


def _counts(vulns: List[Dict]) -> Dict[str, int]:
    c: Dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for v in vulns:
        s = v.get("severity", "low").lower()
        if s in c:
            c[s] += 1
    return c


def _dedup(vulns: List[Dict]) -> List[Dict]:
    seen: set = set()
    out: List[Dict] = []
    for v in vulns:
        k = (v.get("type"), v.get("file", ""), str(v.get("line", "")))
        if k not in seen:
            seen.add(k)
            out.append(v)
    return out


# ── APK analysis ───────────────────────────────────────────────────────────────

def _analyze_manifest(manifest_bytes: bytes) -> List[Dict]:
    vulns: List[Dict] = []

    # Permissions
    perms = _find_permissions_binary(manifest_bytes)
    for perm in perms:
        if perm in DANGEROUS_PERMISSIONS:
            sev, desc = DANGEROUS_PERMISSIONS[perm]
            if sev in ("critical", "high"):
                vulns.append({
                    "type":         f"permission_{perm.lower()}",
                    "severity":     sev,
                    "file":         "AndroidManifest.xml",
                    "line":         None,
                    "code_snippet": f"<uses-permission android:name=\"android.permission.{perm}\"/>",
                    "issue":        f"Dangerous permission: android.permission.{perm}. {desc}",
                    "fix":          "Verify this permission is strictly necessary; request at runtime with clear user rationale.",
                    "cwe":          "CWE-250",
                })

    # Security flags
    for flag_text, vuln_type, sev, issue, fix, cwe in MANIFEST_FLAGS:
        if _find_flags_binary(manifest_bytes, flag_text):
            vulns.append({
                "type":         vuln_type,
                "severity":     sev,
                "file":         "AndroidManifest.xml",
                "line":         None,
                "code_snippet": flag_text,
                "issue":        issue,
                "fix":          fix,
                "cwe":          cwe,
            })

    return vulns


def _scan_text_for_secrets(text: str, filename: str, is_extracted: bool = False) -> List[Dict]:
    """Scan text content for hardcoded secrets and insecure patterns."""
    vulns: List[Dict] = []
    lines = text.splitlines()
    for lineno, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped:
            continue
        for pat, vuln_type, sev, issue, fix, cwe in APK_SECRET_PATTERNS:
            if pat.search(line):
                vulns.append({
                    "type":         vuln_type,
                    "severity":     sev,
                    "file":         filename,
                    "line":         None if is_extracted else lineno,
                    "code_snippet": stripped[:200],
                    "issue":        issue,
                    "fix":          fix,
                    "cwe":          cwe,
                })
                break
    return vulns


def _analyze_smali(text: str, filename: str) -> List[Dict]:
    vulns: List[Dict] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        for pat, vuln_type, sev, issue, fix, cwe in SMALI_PATTERNS:
            if pat.search(line):
                vulns.append({
                    "type":         vuln_type,
                    "severity":     sev,
                    "file":         filename,
                    "line":         lineno,
                    "code_snippet": line.strip()[:200],
                    "issue":        issue,
                    "fix":          fix,
                    "cwe":          cwe,
                })
                break
    return vulns


_TEXT_EXTS = {"xml", "json", "properties", "txt", "gradle", "yaml", "yml",
              "smali", "java", "kt", "kts", "js", "ts", "html", "htm", "cfg", "ini"}


def analyze_apk(apk_bytes: bytes, filename: str) -> Dict[str, Any]:
    """Full static analysis of an Android APK."""
    vulns: List[Dict] = []
    inventory: Dict[str, int] = {}

    try:
        with zipfile.ZipFile(io.BytesIO(apk_bytes), "r") as zf:
            names = zf.namelist()

            # Build inventory
            for name in names:
                ext = name.rsplit(".", 1)[-1].lower() if "." in name else "_noext"
                inventory[ext] = inventory.get(ext, 0) + 1

            # AndroidManifest.xml
            if "AndroidManifest.xml" in names:
                manifest_bytes = zf.read("AndroidManifest.xml")
                vulns.extend(_analyze_manifest(manifest_bytes))

            # All other files
            for name in names:
                if name == "AndroidManifest.xml":
                    continue
                try:
                    data = zf.read(name)
                    ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
                    if ext in _TEXT_EXTS:
                        text = data.decode("utf-8", errors="replace")
                        vulns.extend(_scan_text_for_secrets(text, name))
                        if ext == "smali":
                            vulns.extend(_analyze_smali(text, name))
                    else:
                        # Binary: extract printable strings and scan
                        strings = _extract_ascii_strings(data, min_len=8)
                        if strings:
                            combined = "\n".join(strings)
                            vulns.extend(_scan_text_for_secrets(combined, name, is_extracted=True))
                except Exception:
                    continue

    except zipfile.BadZipFile:
        return {
            "analysis_id":        str(uuid.uuid4()),
            "file_type":          "apk",
            "filename":           filename,
            "total_vulnerabilities": 0,
            "critical": 0, "high": 0, "medium": 0, "low": 0,
            "vulnerabilities":    [],
            "file_inventory":     {},
            "error":              "Invalid APK/ZIP format",
        }

    vulns = _dedup(vulns)
    c = _counts(vulns)

    return {
        "analysis_id":        str(uuid.uuid4()),
        "file_type":          "apk",
        "filename":           filename,
        "total_vulnerabilities": len(vulns),
        **c,
        "vulnerabilities":    vulns,
        "file_inventory": {
            "total_files":      sum(inventory.values()),
            "by_extension":     dict(sorted(inventory.items(), key=lambda x: -x[1])[:15]),
            "has_smali":        "smali" in inventory,
            "has_native_libs":  "so" in inventory,
            "has_dex":          "dex" in inventory,
            "has_kotlin":       "kt" in inventory or "kts" in inventory,
        },
    }


# ── ZIP archive analysis ───────────────────────────────────────────────────────

def analyze_zip(zip_bytes: bytes, filename: str) -> Dict[str, Any]:
    """Analyze all source code files within a ZIP archive."""
    all_vulns: List[Dict] = []
    analyzed: List[str] = []
    skipped: List[str] = []

    try:
        with zipfile.ZipFile(io.BytesIO(zip_bytes), "r") as zf:
            for name in zf.namelist():
                if "/" in name and name.endswith("/"):
                    continue  # directory entry
                ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
                if ext not in EXTENSION_MAP:
                    skipped.append(name)
                    continue
                try:
                    data = zf.read(name)
                    text = data.decode("utf-8", errors="replace")
                    lang = EXTENSION_MAP[ext]
                    result = _base_code_analyze(text, lang, name)
                    for v in result.get("vulnerabilities", []):
                        v.setdefault("file", name)
                        all_vulns.append(v)
                    analyzed.append(name)
                except Exception:
                    skipped.append(name)
                    continue
    except zipfile.BadZipFile:
        return {
            "analysis_id": str(uuid.uuid4()),
            "file_type":   "zip",
            "filename":    filename,
            "total_vulnerabilities": 0,
            "critical": 0, "high": 0, "medium": 0, "low": 0,
            "vulnerabilities": [],
            "error":       "Invalid ZIP file",
        }

    all_vulns = _dedup(all_vulns)
    c = _counts(all_vulns)

    return {
        "analysis_id":        str(uuid.uuid4()),
        "file_type":          "zip",
        "filename":           filename,
        "files_analyzed":     analyzed,
        "files_skipped_count": len(skipped),
        "total_vulnerabilities": len(all_vulns),
        **c,
        "vulnerabilities":    all_vulns,
    }


# ── Code text analysis (wraps base analyzer + Semgrep layer) ──────────────────

def analyze_code(code: str, language: Optional[str], filename: Optional[str]) -> Dict[str, Any]:
    """
    Analyze source code text.
    Runs Bandit/ESLint/pattern rules (via code_analyzer) then layers Semgrep results on top.
    """
    result = _base_code_analyze(code, language, filename)
    result["file_type"] = "code"

    lang = result.get("language", "")
    if lang in SUPPORTED_LANGUAGES:
        sg_vulns, _sg_err = _run_semgrep(code, lang)
        if sg_vulns:
            existing = {(v.get("line"), v.get("cwe")) for v in result.get("vulnerabilities", [])}
            for v in sg_vulns:
                k = (v.get("line"), v.get("cwe"))
                if k not in existing:
                    result["vulnerabilities"].append(v)
                    existing.add(k)

            c = _counts(result["vulnerabilities"])
            result.update(c)
            result["total_vulnerabilities"] = len(result["vulnerabilities"])
            result["semgrep_used"] = True

    return result


# ── Main dispatch ──────────────────────────────────────────────────────────────

def analyze_file(file_bytes: bytes, filename: str, language: Optional[str] = None) -> Dict[str, Any]:
    """
    Auto-detect file type and run the appropriate static analysis.
    Handles APK, ZIP, and text source code files.
    """
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""

    if ext == "apk":
        return analyze_apk(file_bytes, filename)

    if ext == "zip":
        return analyze_zip(file_bytes, filename)

    # Source code file
    try:
        code = file_bytes.decode("utf-8", errors="replace")
    except Exception:
        return {
            "analysis_id": str(uuid.uuid4()),
            "error": "Could not decode file as text",
            "total_vulnerabilities": 0,
            "critical": 0, "high": 0, "medium": 0, "low": 0,
            "vulnerabilities": [],
        }

    if not language and ext in EXTENSION_MAP:
        language = EXTENSION_MAP[ext]

    return analyze_code(code, language, filename)
