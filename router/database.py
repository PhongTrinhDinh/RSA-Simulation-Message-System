"""
database.py — SQLite database cho Router.
"""
import sqlite3
import time
import json
import os

DB_PATH = os.environ.get("DB_PATH", "/app/router.db")


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db():
    conn = get_db()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS public_keys (
            user_id     TEXT PRIMARY KEY,
            public_key  TEXT NOT NULL,
            key_bits    INTEGER,
            e_value     TEXT,
            fingerprint TEXT,
            registered_at INTEGER,
            is_active   BOOLEAN DEFAULT 1
        );
        CREATE TABLE IF NOT EXISTS messages (
            id          TEXT PRIMARY KEY,
            sender      TEXT NOT NULL,
            receiver    TEXT NOT NULL,
            ciphertext  TEXT NOT NULL,
            plaintext   TEXT DEFAULT '',
            padding     TEXT,
            timestamp   INTEGER NOT NULL,
            nonce       TEXT,
            direction   TEXT
        );
        CREATE TABLE IF NOT EXISTS system_config (
            key         TEXT PRIMARY KEY,
            value       TEXT NOT NULL,
            updated_at  INTEGER
        );
        CREATE TABLE IF NOT EXISTS attack_results (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            attack_name TEXT NOT NULL,
            profile     TEXT,
            success     BOOLEAN,
            recovered   TEXT,
            duration_ms INTEGER,
            details     TEXT,
            ran_at      INTEGER
        );
        CREATE TABLE IF NOT EXISTS used_nonces (
            nonce       TEXT PRIMARY KEY,
            used_at     INTEGER NOT NULL
        );
    """)
    # Set default profile
    conn.execute("""
        INSERT OR IGNORE INTO system_config (key, value, updated_at)
        VALUES ('active_profile', 'safe', ?)
    """, (int(time.time()),))
    conn.commit()
    conn.close()


# ── Public Keys ──

def register_key(user_id, public_key_pem, key_bits=0, e_value=0, fingerprint=""):
    conn = get_db()
    conn.execute("""
        INSERT OR REPLACE INTO public_keys
        (user_id, public_key, key_bits, e_value, fingerprint, registered_at, is_active)
        VALUES (?, ?, ?, ?, ?, ?, 1)
    """, (user_id, public_key_pem, key_bits, str(e_value), fingerprint, int(time.time())))
    conn.commit()
    conn.close()


def get_pubkey(user_id):
    conn = get_db()
    row = conn.execute("SELECT * FROM public_keys WHERE user_id=? AND is_active=1",
                       (user_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


def get_all_pubkeys():
    conn = get_db()
    rows = conn.execute("SELECT * FROM public_keys WHERE is_active=1").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def delete_pubkey(user_id):
    conn = get_db()
    conn.execute("UPDATE public_keys SET is_active=0 WHERE user_id=?", (user_id,))
    conn.commit()
    conn.close()


def clear_all_keys():
    conn = get_db()
    conn.execute("DELETE FROM public_keys")
    conn.commit()
    conn.close()


# ── Messages ──

def store_message(msg_id, sender, receiver, ciphertext, plaintext="",
                  padding="", timestamp=0, nonce=""):
    conn = get_db()
    conn.execute("""
        INSERT OR REPLACE INTO messages
        (id, sender, receiver, ciphertext, plaintext, padding, timestamp, nonce, direction)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (msg_id, sender, receiver, ciphertext, plaintext, padding,
          timestamp or int(time.time()), nonce, f"{sender} -> {receiver}"))
    conn.commit()
    conn.close()


def get_messages_for(user_id):
    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM messages WHERE receiver=? ORDER BY timestamp DESC", (user_id,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_all_messages():
    conn = get_db()
    rows = conn.execute("SELECT * FROM messages ORDER BY timestamp DESC").fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ── System Config ──

def get_config(key, default=""):
    conn = get_db()
    row = conn.execute("SELECT value FROM system_config WHERE key=?", (key,)).fetchone()
    conn.close()
    return row["value"] if row else default


def set_config(key, value):
    conn = get_db()
    conn.execute("""
        INSERT OR REPLACE INTO system_config (key, value, updated_at)
        VALUES (?, ?, ?)
    """, (key, value, int(time.time())))
    conn.commit()
    conn.close()


# ── Attack Results ──

def store_attack_result(attack_name, profile, success, recovered="",
                        duration_ms=0, details=""):
    conn = get_db()
    conn.execute("""
        INSERT INTO attack_results (attack_name, profile, success, recovered,
        duration_ms, details, ran_at) VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (attack_name, profile, success, recovered, duration_ms, details,
          int(time.time())))
    conn.commit()
    conn.close()


def get_attack_results():
    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM attack_results ORDER BY ran_at DESC LIMIT 50"
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ── Nonce ──

def check_nonce(nonce):
    """Kiểm tra và đánh dấu nonce đã dùng. Trả về True nếu nonce mới."""
    conn = get_db()
    existing = conn.execute("SELECT 1 FROM used_nonces WHERE nonce=?",
                            (nonce,)).fetchone()
    if existing:
        conn.close()
        return False
    conn.execute("INSERT INTO used_nonces (nonce, used_at) VALUES (?, ?)",
                 (nonce, int(time.time())))
    conn.commit()
    conn.close()
    return True


def reset_all():
    conn = get_db()
    conn.executescript("""
        DELETE FROM public_keys;
        DELETE FROM messages;
        DELETE FROM used_nonces;
        DELETE FROM attack_results;
    """)
    set_config("active_profile", "safe")
    conn.close()
