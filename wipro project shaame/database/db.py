import sqlite3
import os
from pathlib import Path
from contextlib import contextmanager
from config.config import Config

DB_PATH = Path(Config.DATABASE_PATH)

def get_db_connection():
    """Returns a new SQLite connection with row factory set to sqlite3.Row."""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH), timeout=20.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn

@contextmanager
def get_db():
    """Context manager for thread-safe SQLite operations."""
    conn = get_db_connection()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

def init_db():
    """Initializes SQLite database tables from schema.sql."""
    schema_path = Path(__file__).resolve().parent / "schema.sql"
    with open(schema_path, "r", encoding="utf-8") as f:
        schema_sql = f.read()

    with get_db() as conn:
        conn.executescript(schema_sql)
        # Initialize default settings if not existing
        settings = [
            ("ml_contamination", str(Config.ML_CONTAMINATION_RATE)),
            ("ml_anomaly_threshold", str(Config.ML_ANOMALY_THRESHOLD)),
            ("llm_provider", Config.LLM_PROVIDER),
            ("aws_integration_status", "Simulation / Local Prototype Active")
        ]
        for k, v in settings:
            conn.execute(
                "INSERT OR IGNORE INTO system_settings (key, value, updated_at) VALUES (?, ?, datetime('now'))",
                (k, v)
            )

def query_one(query, params=()):
    """Execute a single-row query and return dict or None."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(query, params)
        row = cursor.fetchone()
        return dict(row) if row else None

def query_all(query, params=()):
    """Execute query and return list of dicts."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(query, params)
        rows = cursor.fetchall()
        return [dict(r) for r in rows]

def execute_insert(query, params=()):
    """Execute an insert query and return the last inserted row id."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(query, params)
        return cursor.lastrowid

def execute_update(query, params=()):
    """Execute update/delete query and return rowcount affected."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(query, params)
        return cursor.rowcount
