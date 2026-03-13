import hashlib
import json
import sqlite3
from datetime import datetime, timezone


def _now_iso() -> str:
    """Return current UTC time as ISO-8601 string."""
    return datetime.now(timezone.utc).isoformat()


def _stable_json(obj) -> str:
    """
    Deterministic JSON encoding:
    - sorted keys
    - no unnecessary whitespace
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _sha256(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def init_chain(conn: sqlite3.Connection) -> None:
    """
    Ensure the chain_blocks table exists and create a GENESIS block if empty.
    """
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS chain_blocks (
            idx INTEGER PRIMARY KEY,
            ts TEXT NOT NULL,
            prev_hash TEXT NOT NULL,
            hash TEXT NOT NULL,
            event_type TEXT NOT NULL,
            payload_json TEXT NOT NULL
        )
    """)
    conn.commit()

    c.execute("SELECT COUNT(*) FROM chain_blocks")
    (n,) = c.fetchone()
    if n == 0:
        append_block(conn, "GENESIS", {"genesis": True})


def append_block(conn: sqlite3.Connection, event_type: str, payload: dict) -> int:
    """
    Append an audit event to the permissioned chain.

    The block hash is over:
        idx | ts | prev_hash | event_type | payload_json

    Returns the new block index.
    """
    c = conn.cursor()
    c.execute("SELECT idx, hash FROM chain_blocks ORDER BY idx DESC LIMIT 1")
    row = c.fetchone()
    if row:
        last_idx, last_hash = row
        idx = last_idx + 1
        prev_hash = last_hash
    else:
        idx = 0
        prev_hash = "0" * 64

    ts = _now_iso()
    payload_json = _stable_json(payload)
    material = f"{idx}|{ts}|{prev_hash}|{event_type}|{payload_json}"
    h = _sha256(material)

    c.execute(
        "INSERT INTO chain_blocks (idx, ts, prev_hash, hash, event_type, payload_json) "
        "VALUES (?,?,?,?,?,?)",
        (idx, ts, prev_hash, h, event_type, payload_json),
    )
    conn.commit()
    return idx


def verify_chain(conn: sqlite3.Connection) -> tuple[bool, str]:
    """
    Verify the chain integrity:
    - prev_hash linkage
    - hash matches recomputed material

    Returns (ok: bool, message: str).
    """
    c = conn.cursor()
    c.execute("SELECT idx, ts, prev_hash, hash, event_type, payload_json "
              "FROM chain_blocks ORDER BY idx ASC")
    rows = c.fetchall()
    if not rows:
        return False, "No blocks found."

    prev = "0" * 64
    for (idx, ts, prev_hash, h, event_type, payload_json) in rows:
        if prev_hash != prev:
            return False, f"Broken prev_hash at block {idx}."
        material = f"{idx}|{ts}|{prev_hash}|{event_type}|{payload_json}"
        expected = _sha256(material)
        if expected != h:
            return False, f"Hash mismatch at block {idx}."
        prev = h

    return True, f"OK ({len(rows)} blocks)."
