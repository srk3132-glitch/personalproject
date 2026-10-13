import asyncio, json, time, uuid
from collections import defaultdict, deque
from pathlib import Path
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, PlainTextResponse
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
import ai, auth, db, scanner

app = FastAPI(title="CodeShield AI")
FRONT = Path(__file__).parent.parent / "frontend"
db.init()

HITS = defaultdict(deque)   # in-memory limiter; with several server instances, move this to Redis
def hit(key: str, n: int, window: int, msg="Too many requests, slow down."):
    now, q = time.time(), HITS[key]
    while q and now - q[0] > window: q.popleft()
    if len(q) >= n: raise HTTPException(429, msg)
    q.append(now)

class Cred(BaseModel):
    email: str = Field(max_length=200)
    password: str = Field(min_length=8, max_length=200)
class CodeIn(BaseModel):
    code: str = Field(max_length=200_000)
    language: str = "python"
    use_ai: bool = True
class RepoIn(BaseModel):
    url: str

# ---------------- auth ----------------
@app.post("/api/auth/register")
def register(b: Cred, req: Request):
    hit("auth:" + req.client.host, 10, 900, "Too many attempts. Try again in 15 minutes.")
    email = b.email.strip().lower()
    if "@" not in email or "." not in email.split("@")[-1]: raise HTTPException(400, "Enter a valid email.")
    uid = uuid.uuid4().hex
    try:
        with db.engine.begin() as c:
            c.execute(text("INSERT INTO users(id,email,pw,created) VALUES(:i,:e,:p,:t)"),
                      {"i": uid, "e": email, "p": auth.hash_pw(b.password), "t": time.time()})
    except IntegrityError:
        raise HTTPException(409, "That email is already registered.")
    return {"token": auth.make_token(uid), "email": email}

@app.post("/api/auth/login")
def login(b: Cred, req: Request):
    hit("auth:" + req.client.host, 10, 900, "Too many attempts. Try again in 15 minutes.")
    email = b.email.strip().lower()
    with db.engine.begin() as c:
        u = c.execute(text("SELECT id, pw FROM users WHERE email=:e"), {"e": email}).mappings().first()
    if not u or not auth.check_pw(b.password, u["pw"]): raise HTTPException(401, "Invalid email or password.")
    return {"token": auth.make_token(u["id"]), "email": email}

# ---------------- scanning ----------------
def summarize(fs):
    s = {"total": len(fs), "high": 0, "medium": 0, "low": 0, "files": {}, "types": {}}
    for f in fs:
        s[f["severity"]] += 1
        s["files"][f["file"]] = s["files"].get(f["file"], 0) + 1
        s["types"][f["rule_id"]] = s["types"].get(f["rule_id"], 0) + 1
    s["files"] = dict(sorted(s["files"].items(), key=lambda x: -x[1])[:8])
    s["types"] = dict(sorted(s["types"].items(), key=lambda x: -x[1])[:8])
    s["risk_score"] = min(100, s["high"] * 10 + s["medium"] * 4 + s["low"])
    s["engine"] = fs[0]["engine"] if fs else ("semgrep" if scanner.semgrep_available() else "regex-fallback")
    return s

def save(uid, source, language, fs):
    sid, summ = uuid.uuid4().hex[:10], summarize(fs)
    with db.engine.begin() as c:   # findings + snippets only, never the full source
        c.execute(text("INSERT INTO scans(id,user_id,created,source,language,summary,findings) VALUES(:i,:u,:t,:s,:l,:m,:f)"),
                  {"i": sid, "u": uid, "t": time.time(), "s": source, "l": language, "m": json.dumps(summ), "f": json.dumps(fs)})
    return {"id": sid, "summary": summ, "findings": fs}

@app.post("/api/scan/code")
async def scan_code(body: CodeIn, uid: str = Depends(auth.current_user)):
    hit("scan:" + uid, 20, 3600, "Limit reached: 20 scans per hour.")
    fs = await asyncio.to_thread(scanner.scan_code, body.code, body.language)
    if body.use_ai:
        await ai.triage_all(fs, lambda f: scanner.context_for(body.code, f["line"]), body.language)
    for f in fs:
        f["ml_score"] = await asyncio.to_thread(ai.ml_score, scanner.context_for(body.code, f["line"], 8))
    return save(uid, "pasted code", body.language, fs)

@app.post("/api/scan/repo")
async def scan_repo(body: RepoIn, uid: str = Depends(auth.current_user)):
    hit("scan:" + uid, 20, 3600, "Limit reached: 20 scans per hour.")
    try: fs = await asyncio.to_thread(scanner.scan_repo, body.url)
    except ValueError as e: raise HTTPException(400, str(e))
    except Exception: raise HTTPException(502, "Could not clone or scan that repository.")
    return save(uid, body.url, "mixed", fs)

# ---------------- history / reports ----------------
@app.get("/api/scans")
def history(uid: str = Depends(auth.current_user)):
    with db.engine.begin() as c:
        rows = c.execute(text("SELECT id, created, source, summary FROM scans WHERE user_id=:u ORDER BY created DESC LIMIT 30"),
                         {"u": uid}).mappings().all()
    return [{**dict(r), "summary": json.loads(r["summary"])} for r in rows]

def _get(sid, uid):
    with db.engine.begin() as c:
        r = c.execute(text("SELECT * FROM scans WHERE id=:i AND user_id=:u"), {"i": sid, "u": uid}).mappings().first()
    if not r: raise HTTPException(404, "Scan not found.")
    return {"id": sid, "source": r["source"], "summary": json.loads(r["summary"]), "findings": json.loads(r["findings"])}

@app.get("/api/scans/{sid}")
def get_scan(sid: str, uid: str = Depends(auth.current_user)): return _get(sid, uid)

@app.delete("/api/scans/{sid}")
def delete_scan(sid: str, uid: str = Depends(auth.current_user)):
    with db.engine.begin() as c:
        c.execute(text("DELETE FROM scans WHERE id=:i AND user_id=:u"), {"i": sid, "u": uid})
    return {"ok": True}

@app.get("/api/scans/{sid}/report.md", response_class=PlainTextResponse)
def report(sid: str, uid: str = Depends(auth.current_user)):
    d = _get(sid, uid); s = d["summary"]
    out = [f"# CodeShield AI report\n\n**Source:** {d['source']}  \n**Risk score:** {s['risk_score']}/100  \n"
           f"**Findings:** {s['total']} (high {s['high']}, medium {s['medium']}, low {s['low']})\n\n> AI output is advisory; verify before applying.\n"]
    for f in d["findings"]:
        out.append(f"## [{f['severity'].upper()}] {f['rule_id']} - {f['file']}:{f['line']}\n\n{f['message']}\n\n```\n{f['evidence']}\n```\n")
        a = f.get("ai")
        if a:
            out.append(f"**AI verdict:** {'likely vulnerable' if a.get('is_likely_vulnerable') else 'likely false positive'} ({a.get('confidence')})\n\n"
                       f"**Impact:** {a.get('impact')}\n\n**Fix:** {a.get('remediation')}\n\n```\n{a.get('patched_code')}\n```\n")
    return "\n".join(out)

@app.get("/healthz")
def health(): return {"ok": True}

@app.get("/")
def index(): return FileResponse(FRONT / "index.html")
