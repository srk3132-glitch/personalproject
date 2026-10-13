"""Postgres in production (DATABASE_URL), SQLite file locally."""
import os
from sqlalchemy import create_engine, text

URL = os.getenv("DATABASE_URL", "sqlite:///codeshield.db")
if URL.startswith("postgres://"): URL = URL.replace("postgres://", "postgresql+psycopg://", 1)
elif URL.startswith("postgresql://"): URL = URL.replace("postgresql://", "postgresql+psycopg://", 1)
engine = create_engine(URL, pool_pre_ping=True)

def init():
    with engine.begin() as c:
        c.execute(text("CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY, email TEXT UNIQUE NOT NULL, pw TEXT NOT NULL, created DOUBLE PRECISION)"))
        c.execute(text("CREATE TABLE IF NOT EXISTS scans(id TEXT PRIMARY KEY, user_id TEXT NOT NULL, created DOUBLE PRECISION, "
                       "source TEXT, language TEXT, summary TEXT, findings TEXT)"))
        c.execute(text("CREATE INDEX IF NOT EXISTS scans_user ON scans(user_id, created)"))
