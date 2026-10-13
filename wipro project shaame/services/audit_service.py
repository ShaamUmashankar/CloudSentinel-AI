from datetime import datetime
from typing import Dict, Any, List
from database.db import get_db, query_all

class AuditService:
    """
    Maintains an immutable audit trail for security operations,
    incident status modifications, and simulated containment actions.
    """

    @classmethod
    def log_action(cls, category: str, action: str, actor: str, target_id: str, details: str, status: str = "SUCCESS", ip: str = "127.0.0.1") -> int:
        timestamp = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO audit_trail (
                    action_category, action_name, actor, target_id, details,
                    status, ip_address, timestamp
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (category, action, actor, str(target_id), details, status, ip, timestamp))
            return cursor.lastrowid

    @classmethod
    def get_recent_logs(cls, limit: int = 50) -> List[Dict[str, Any]]:
        return query_all("""
            SELECT * FROM audit_trail
            ORDER BY id DESC
            LIMIT ?
        """, (limit,))
