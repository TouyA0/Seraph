import json
import os
import time

import aiosqlite

DB_PATH = os.getenv("DATABASE_URL", "sqlite+aiosqlite:////data/seraph.db").replace(
    "sqlite+aiosqlite:////", "/"
).replace("sqlite+aiosqlite:///", "")

_CREATE_SQL = """
CREATE TABLE IF NOT EXISTS investigations (
    id          TEXT PRIMARY KEY,
    artifact    TEXT NOT NULL,
    type        TEXT NOT NULL,
    created_at  REAL NOT NULL,
    status      TEXT NOT NULL DEFAULT 'pending',
    score       INTEGER,
    results_json TEXT
);
"""


async def get_db() -> aiosqlite.Connection:
    os.makedirs(os.path.dirname(DB_PATH) if "/" in DB_PATH else ".", exist_ok=True)
    db = await aiosqlite.connect(DB_PATH)
    db.row_factory = aiosqlite.Row
    await db.execute(_CREATE_SQL)
    await db.commit()
    return db


async def save_investigation(inv_id: str, artifact: str, artifact_type: str, results: list[dict]) -> None:
    db = await get_db()
    try:
        await db.execute(
            "INSERT OR REPLACE INTO investigations (id, artifact, type, created_at, status, results_json) VALUES (?, ?, ?, ?, 'done', ?)",
            (inv_id, artifact, artifact_type, time.time(), json.dumps(results)),
        )
        await db.commit()
    finally:
        await db.close()


async def list_investigations(limit: int = 20) -> list[dict]:
    db = await get_db()
    try:
        async with db.execute(
            "SELECT id, artifact, type, created_at, status, score FROM investigations ORDER BY created_at DESC LIMIT ?",
            (limit,),
        ) as cursor:
            rows = await cursor.fetchall()
            return [dict(r) for r in rows]
    finally:
        await db.close()


async def get_investigation(inv_id: str) -> dict | None:
    db = await get_db()
    try:
        async with db.execute(
            "SELECT * FROM investigations WHERE id = ?", (inv_id,)
        ) as cursor:
            row = await cursor.fetchone()
            if not row:
                return None
            d = dict(row)
            if d.get("results_json"):
                d["results"] = json.loads(d["results_json"])
            return d
    finally:
        await db.close()
