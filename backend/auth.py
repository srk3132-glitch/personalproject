"""Password hashing (scrypt) and signed expiring tokens. No extra dependencies."""
import base64, hashlib, hmac, json, os, secrets, time
from fastapi import HTTPException, Request

SECRET = os.getenv("SECRET_KEY") or secrets.token_hex(32)   # set SECRET_KEY in production or logins reset on restart
TTL = 7 * 86400

def hash_pw(pw: str) -> str:
    salt = os.urandom(16)
    return salt.hex() + "$" + hashlib.scrypt(pw.encode(), salt=salt, n=2**14, r=8, p=1).hex()

def check_pw(pw: str, stored: str) -> bool:
    try: salt, h = stored.split("$")
    except ValueError: return False
    cand = hashlib.scrypt(pw.encode(), salt=bytes.fromhex(salt), n=2**14, r=8, p=1).hex()
    return hmac.compare_digest(cand, h)

def _sig(body: bytes) -> str:
    return hmac.new(SECRET.encode(), body, hashlib.sha256).hexdigest()

def make_token(uid: str) -> str:
    body = base64.urlsafe_b64encode(json.dumps({"u": uid, "e": int(time.time()) + TTL}).encode())
    return body.decode() + "." + _sig(body)

def verify_token(tok: str):
    try:
        body, sig = tok.split(".")
        if not hmac.compare_digest(sig, _sig(body.encode())): return None
        d = json.loads(base64.urlsafe_b64decode(body))
        return d["u"] if d["e"] > time.time() else None
    except Exception:
        return None

def current_user(request: Request) -> str:
    h = request.headers.get("authorization", "")
    uid = verify_token(h[7:]) if h.startswith("Bearer ") else None
    if not uid: raise HTTPException(401, "Please log in.")
    return uid
