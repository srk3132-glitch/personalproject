"""Static scanning layer. Never executes scanned code."""
import json, os, re, shutil, subprocess, tempfile
from pathlib import Path

EXT = {"python": ".py", "javascript": ".js", "typescript": ".ts", "java": ".java", "php": ".php", "go": ".go"}
SKIP_DIRS = {".git", "node_modules", "venv", ".venv", "dist", "build", "__pycache__"}
CODE_EXT = set(EXT.values()) | {".jsx", ".tsx"}
SEV = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}
MAX_FILES, MAX_BYTES = 800, 1_000_000

# Fallback rules so the app still works if Semgrep isn't installed.
FALLBACK = [
    (r"(execute|query)\s*\(.*(\+|%|f['\"]|\.format\().*", "sql-injection", "high", "SQL built from string concatenation/formatting."),
    (r"\beval\s*\(|\bexec\s*\(", "code-injection", "high", "eval/exec on dynamic data."),
    (r"os\.system\(|shell\s*=\s*True", "command-injection", "high", "Shell command execution."),
    (r"pickle\.loads?\(|yaml\.load\((?!.*Loader)", "insecure-deserialization", "high", "Unsafe deserialization."),
    (r"(?i)(api[_-]?key|secret|passwd|password|token)\s*[:=]\s*['\"][^'\"]{8,}['\"]", "hardcoded-secret", "high", "Possible hard-coded secret."),
    (r"hashlib\.(md5|sha1)\(|\bMath\.random\(", "weak-crypto", "medium", "Weak hash / insecure randomness."),
    (r"verify\s*=\s*False", "tls-verification-disabled", "medium", "TLS verification disabled."),
    (r"\.innerHTML\s*=|dangerouslySetInnerHTML|document\.write\(", "xss", "medium", "Unescaped HTML sink."),
    (r"open\(.*(request|input|argv)", "path-traversal", "medium", "File path from user input."),
    (r"requests\.(get|post)\(\s*(request|url|user)", "ssrf", "medium", "Server fetches user-controlled URL."),
]

def semgrep_available() -> bool:
    return shutil.which("semgrep") is not None

def _run_semgrep(target: str) -> list[dict]:
    cmd = ["semgrep", "--config", "p/security-audit", "--config", "p/secrets", "--json",
           "--quiet", "--timeout", "20", "--max-target-bytes", "1000000", target]
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    data = json.loads(p.stdout or "{}")
    out = []
    for r in data.get("results", []):
        meta = r["extra"].get("metadata", {})
        cwe = meta.get("cwe", "")
        out.append({
            "rule_id": r["check_id"].split(".")[-1], "file": os.path.relpath(r["path"], target),
            "line": r["start"]["line"], "end_line": r["end"]["line"],
            "severity": SEV.get(r["extra"].get("severity", "INFO"), "low"),
            "message": r["extra"].get("message", ""), "evidence": r["extra"].get("lines", ""),
            "cwe": ", ".join(cwe) if isinstance(cwe, list) else str(cwe), "engine": "semgrep"})
    return out

def iter_files(root: str):
    n = 0
    for dp, dn, fn in os.walk(root):
        dn[:] = [d for d in dn if d not in SKIP_DIRS]
        for f in fn:
            p = os.path.join(dp, f)
            if Path(f).suffix in CODE_EXT and os.path.getsize(p) < MAX_BYTES:
                n += 1
                if n > MAX_FILES: return
                yield p

def _run_fallback(root: str) -> list[dict]:
    out = []
    for f in iter_files(root):
        try: lines = Path(f).read_text(errors="ignore").splitlines()
        except Exception: continue
        for i, line in enumerate(lines, 1):
            for pat, rid, sev, msg in FALLBACK:
                if re.search(pat, line):
                    out.append({"rule_id": rid, "file": os.path.relpath(f, root), "line": i, "end_line": i,
                                "severity": sev, "message": msg, "evidence": line.strip(), "cwe": "", "engine": "regex-fallback"})
    return out

def scan_dir(root: str) -> list[dict]:
    if semgrep_available():
        try: return _run_semgrep(root)
        except Exception: pass
    return _run_fallback(root)

def scan_code(code: str, language: str) -> list[dict]:
    d = tempfile.mkdtemp(prefix="cs_")
    try:
        (Path(d) / f"snippet{EXT.get(language, '.py')}").write_text(code)
        return scan_dir(d)
    finally:
        shutil.rmtree(d, ignore_errors=True)

GH = re.compile(r"^https://github\.com/[\w.-]+/[\w.-]+?(\.git)?/?$")

def scan_repo(url: str) -> list[dict]:
    if not GH.match(url): raise ValueError("Only public https://github.com/<owner>/<repo> URLs are supported.")
    d = tempfile.mkdtemp(prefix="csrepo_")
    try:
        subprocess.run(["git", "clone", "--depth", "1", "--no-tags", url, d], check=True, timeout=120,
                       capture_output=True, env={**os.environ, "GIT_TERMINAL_PROMPT": "0"})
        return scan_dir(d)  # static only; repo code is never run
    finally:
        shutil.rmtree(d, ignore_errors=True)

def context_for(code: str, line: int, radius: int = 15) -> str:
    ls = code.splitlines()
    a, b = max(0, line - 1 - radius), min(len(ls), line + radius)
    return "\n".join(f"{i+1}: {ls[i]}" for i in range(a, b))
