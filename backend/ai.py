"""AI layer: secret masking, LLM triage + patch, optional locally-trained classifier."""
import asyncio, json, os, re
import httpx

API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
MODEL = os.getenv("CS_MODEL", "claude-sonnet-5-5")
MODEL_DIR = os.getenv("CS_CLASSIFIER_DIR", "../training/out")

SECRET_PATTERNS = [r"AKIA[0-9A-Z]{16}", r"ghp_[A-Za-z0-9]{36}", r"sk-[A-Za-z0-9_-]{20,}", r"xox[baprs]-[A-Za-z0-9-]{10,}"]
KV = r"(?i)((?:api[_-]?key|secret|password|passwd|token)\s*[:=]\s*['\"])[^'\"]{6,}(['\"])"
def mask_secrets(text: str) -> str:
    for p in SECRET_PATTERNS: text = re.sub(p, "<REDACTED>", text)
    return re.sub(KV, r"\1<REDACTED>\2", text)

SYSTEM = ("You are a senior application-security reviewer. Given a static-analysis finding and code context, "
          "decide if it is a real vulnerability. Reply with ONLY a JSON object with keys: "
          "is_likely_vulnerable (bool), confidence (low|medium|high), vulnerability (str), impact (str), "
          "evidence (str), remediation (str), patched_code (str, the fixed version of the vulnerable lines), "
          "exploit_scenario (str, 1-2 sentences, no weaponized payloads). Be conservative about false positives.")

async def triage(client, finding: dict, context: str, language: str):
    if not API_KEY: return None
    prompt = (f"Language: {language}\nRule: {finding['rule_id']} ({finding['cwe']})\nScanner message: {finding['message']}\n"
              f"Flagged line {finding['line']}.\n\nCode context:\n{mask_secrets(context)}")
    try:
        r = await client.post("https://api.anthropic.com/v1/messages",
            headers={"x-api-key": API_KEY, "anthropic-version": "2023-06-01", "content-type": "application/json"},
            json={"model": MODEL, "max_tokens": 900, "system": SYSTEM, "messages": [{"role": "user", "content": prompt}]},
            timeout=60)
        text = "".join(b.get("text", "") for b in r.json().get("content", []))
        return json.loads(re.sub(r"^```(?:json)?|```$", "", text.strip(), flags=re.M).strip())
    except Exception:
        return None

async def triage_all(findings, get_code, language: str, limit: int = 15):
    sem = asyncio.Semaphore(4)
    order = {"high": 0, "medium": 1, "low": 2}
    todo = sorted(findings, key=lambda f: order[f["severity"]])[:limit]
    async with httpx.AsyncClient() as c:
        async def one(f):
            async with sem:
                f["ai"] = await triage(c, f, get_code(f), language)
        await asyncio.gather(*(one(f) for f in todo))

# ---- optional: your own fine-tuned classifier (see training/train_classifier.py) ----
_clf = None
def ml_score(snippet: str):
    """Probability a snippet is vulnerable from your fine-tuned model; None if no model is present."""
    global _clf
    if _clf is None:
        if not os.path.isdir(MODEL_DIR): _clf = False
        else:
            from transformers import pipeline
            _clf = pipeline("text-classification", model=MODEL_DIR, truncation=True, max_length=512, top_k=None)
    if not _clf: return None
    res = _clf(snippet[:4000])[0]
    return next(x["score"] for x in res if x["label"] in ("LABEL_1", "vulnerable"))
