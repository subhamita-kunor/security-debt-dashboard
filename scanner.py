"""
Security Vulnerability & Technical Debt Scanner
Scans source files for anti-patterns, hardcoded secrets, deprecated APIs,
and code defects. Outputs findings to security_debt_log.json.
"""

import os
import re
import json
import sys
import hashlib
from datetime import datetime, timezone
from pathlib import Path

# ── Target file extensions ────────────────────────────────────────────────────
SOURCE_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".java",
    ".rb", ".php", ".c", ".cpp", ".cs", ".sh", ".yaml", ".yml",
    ".env", ".conf", ".config", ".xml", ".tf", ".hcl",
}

# ── Directories to skip ───────────────────────────────────────────────────────
SKIP_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv", "dist",
    "build", ".idea", ".vscode", "vendor", "site-packages",
}

# ── Rule definitions ──────────────────────────────────────────────────────────
# Each rule: (category, severity, description, regex_pattern)
RULES = [
    # ── Hardcoded Secrets & Tokens ─────────────────────────────────────────
    ("Hardcoded Secret", "High",
     "Generic password assignment in source",
     r'(?i)(password|passwd|pwd)\s*=\s*["\'][^"\']{4,}["\']'),

    ("Hardcoded Secret", "High",
     "Hardcoded API key or token variable",
     r'(?i)(api_key|apikey|api_token|auth_token|secret_key|access_token)\s*=\s*["\'][A-Za-z0-9/+_\-]{8,}["\']'),

    ("Hardcoded Secret", "High",
     "AWS Access Key ID pattern",
     r'AKIA[0-9A-Z]{16}'),

    ("Hardcoded Secret", "High",
     "AWS Secret Access Key pattern",
     r'(?i)aws_secret_access_key\s*=\s*["\'][A-Za-z0-9/+=]{40}["\']'),

    ("Hardcoded Secret", "High",
     "Generic private key header in source",
     r'-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----'),

    ("Hardcoded Secret", "High",
     "GitHub / GitLab personal access token",
     r'(?:ghp|gho|ghu|ghs|ghr|glpat)_[A-Za-z0-9_]{20,}'),

    ("Hardcoded Secret", "Medium",
     "Connection string with embedded credentials",
     r'(?i)(jdbc:|mongodb\+srv?:|postgres://|mysql://)[^"\'<\s]*:[^"\'<\s]*@'),

    ("Hardcoded Secret", "Medium",
     "Bearer token literal",
     r'(?i)bearer\s+[A-Za-z0-9\-._~+/]+=*'),

    # ── Injection Vulnerabilities ──────────────────────────────────────────
    ("Injection", "High",
     "Potential SQL injection via string concatenation",
     r'(?i)(execute|query|cursor\.execute)\s*\(\s*["\']?\s*(SELECT|INSERT|UPDATE|DELETE|DROP)[^)]*\+'),

    ("Injection", "High",
     "eval() called with dynamic input (Code Injection)",
     r'\beval\s*\(\s*(?![\'"]\s*\))'),

    ("Injection", "High",
     "OS command injection risk (shell=True)",
     r'subprocess\.(call|run|Popen)\s*\([^)]*shell\s*=\s*True'),

    ("Injection", "High",
     "Dangerous exec() with non-literal argument",
     r'\bexec\s*\(\s*(?!["\'])'),

    ("Injection", "Medium",
     "Unparameterised pymongo query with user input risk",
     r'\.find\(\s*\{[^}]*request\.(args|form|json|data)'),

    # ── Cryptography ──────────────────────────────────────────────────────
    ("Cryptography", "High",
     "Use of broken MD5 hash function",
     r'(?i)\b(md5|hashlib\.md5)\b'),

    ("Cryptography", "High",
     "Use of broken SHA-1 hash function",
     r'(?i)\b(sha1|hashlib\.sha1)\b'),

    ("Cryptography", "High",
     "DES/3DES cipher usage (weak encryption)",
     r'(?i)\b(DES|3DES|TripleDES)\b'),

    ("Cryptography", "Medium",
     "SSL/TLS verification disabled",
     r'(?i)(verify\s*=\s*False|ssl_verify\s*=\s*False|check_hostname\s*=\s*False)'),

    ("Cryptography", "Medium",
     "Hardcoded IV / nonce (ECB mode risk)",
     r'(?i)(\.encrypt\s*\(|MODE_ECB|AES\.MODE_ECB)'),

    ("Cryptography", "Low",
     "Random used for security-sensitive purpose (use secrets module)",
     r'(?i)random\.(random|randint|choice|seed)\s*\('),

    # ── Insecure Deserialization ───────────────────────────────────────────
    ("Insecure Deserialization", "High",
     "pickle.loads() called — arbitrary code execution risk",
     r'\bpickle\.(loads?|Unpickler)'),

    ("Insecure Deserialization", "High",
     "PyYAML unsafe yaml.load() without Loader",
     r'\byaml\.load\s*\(\s*(?![^)]*Loader\s*=\s*yaml\.SafeLoader)'),

    ("Insecure Deserialization", "Medium",
     "marshal.loads() — deserialization risk",
     r'\bmarshal\.(loads?)\b'),

    # ── Path Traversal ─────────────────────────────────────────────────────
    ("Path Traversal", "High",
     "open() with user-controlled path (no sanitization visible)",
     r'\bopen\s*\([^)]*request\.(args|form|json|data|files)'),

    ("Path Traversal", "Medium",
     "os.path.join with raw user input",
     r'os\.path\.join\s*\([^)]*request\.(args|form|json|data)'),

    # ── Security Misconfiguration ──────────────────────────────────────────
    ("Security Misconfiguration", "High",
     "Flask debug mode enabled in production",
     r'(?i)(app\.run\s*\([^)]*debug\s*=\s*True|DEBUG\s*=\s*True)'),

    ("Security Misconfiguration", "High",
     "CORS allow-all origin wildcard",
     r'(?i)(Access-Control-Allow-Origin\s*[:=]\s*["\']?\*|origins\s*=\s*["\']?\*)'),

    ("Security Misconfiguration", "Medium",
     "Insecure HTTP endpoint (non-TLS)",
     r'(?i)http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0)[a-zA-Z0-9]'),

    ("Security Misconfiguration", "Medium",
     "Docker or K8s running as root user",
     r'(?i)(USER\s+root|runAsUser:\s*0\b)'),

    # ── Code Smell / Technical Debt ────────────────────────────────────────
    ("Code Smell", "Low",
     "TODO / FIXME / HACK comment indicating unfinished work",
     r'(?i)#\s*(TODO|FIXME|HACK|XXX|BUG)\b'),

    ("Code Smell", "Low",
     "Broad exception catch suppresses errors",
     r'except\s*:\s*$|except\s+Exception\s*:\s*$|except\s+Exception\s+as\s+\w+\s*:\s*pass'),

    ("Code Smell", "Low",
     "print() used for logging in production code",
     r'\bprint\s*\('),

    ("Code Smell", "Low",
     "Commented-out code block",
     r'(?i)^\s*#\s*(if |for |while |def |class |return |import )'),

    ("Deprecated API", "Medium",
     "Python 2 print statement style (py3 compat risk)",
     r'^\s*print\s+["\'][^(]'),

    ("Deprecated API", "Medium",
     "Use of deprecated os.popen (use subprocess)",
     r'\bos\.popen\s*\('),

    ("Deprecated API", "Low",
     "Use of deprecated imp module (use importlib)",
     r'\bimport\s+imp\b|\bimp\.(load_source|find_module)\b'),
]

# ── Scanner core ──────────────────────────────────────────────────────────────

def scan_file(filepath: Path) -> list[dict]:
    """Return a list of finding dicts for a single file."""
    findings = []
    try:
        content = filepath.read_text(encoding="utf-8", errors="replace")
    except (OSError, PermissionError):
        return findings

    lines = content.splitlines()
    for lineno, line in enumerate(lines, start=1):
        for category, severity, description, pattern in RULES:
            match = re.search(pattern, line)
            if match:
                # Truncate detected text for readability
                detected = line.strip()[:120]
                findings.append({
                    "file_path": str(filepath).replace("\\", "/"),
                    "line_number": lineno,
                    "defect_category": category,
                    "severity": severity,
                    "description": description,
                    "detected_text": detected,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    # Stable dedup key
                    "_id": hashlib.sha1(
                        f"{filepath}:{lineno}:{pattern}".encode()
                    ).hexdigest()[:12],
                })
    return findings


def scan_directory(root: str) -> list[dict]:
    """Recursively walk root and scan all eligible source files."""
    all_findings: list[dict] = []
    root_path = Path(root).resolve()

    for dirpath, dirnames, filenames in os.walk(root_path):
        # Prune skip dirs in-place so os.walk won't descend into them
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]

        for filename in filenames:
            filepath = Path(dirpath) / filename
            if filepath.suffix.lower() in SOURCE_EXTENSIONS:
                file_findings = scan_file(filepath)
                all_findings.extend(file_findings)

    return all_findings


# ── JSON database persistence ─────────────────────────────────────────────────

DB_FILE = "security_debt_log.json"


def load_db() -> list[dict]:
    if os.path.exists(DB_FILE):
        with open(DB_FILE, "r", encoding="utf-8") as f:
            try:
                return json.load(f)
            except json.JSONDecodeError:
                return []
    return []


def save_db(records: list[dict]) -> None:
    with open(DB_FILE, "w", encoding="utf-8") as f:
        json.dump(records, f, indent=2, ensure_ascii=False)


def merge_findings(existing: list[dict], new_findings: list[dict]) -> list[dict]:
    """Upsert by _id so re-runs don't create duplicate entries."""
    existing_by_id = {r["_id"]: r for r in existing}
    for finding in new_findings:
        existing_by_id[finding["_id"]] = finding
    return list(existing_by_id.values())


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    scan_root = sys.argv[1] if len(sys.argv) > 1 else "."
    print(f"[scanner] Scanning: {Path(scan_root).resolve()}")

    new_findings = scan_directory(scan_root)
    print(f"[scanner] Raw findings: {len(new_findings)}")

    existing = load_db()
    merged = merge_findings(existing, new_findings)
    save_db(merged)

    high   = sum(1 for f in new_findings if f["severity"] == "High")
    medium = sum(1 for f in new_findings if f["severity"] == "Medium")
    low    = sum(1 for f in new_findings if f["severity"] == "Low")

    print(f"[scanner] Severity breakdown — High: {high}, Medium: {medium}, Low: {low}")
    print(f"[scanner] Database updated → {DB_FILE}  (total records: {len(merged)})")


if __name__ == "__main__":
    main()
