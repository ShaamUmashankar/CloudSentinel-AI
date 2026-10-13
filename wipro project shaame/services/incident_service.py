import json
import uuid
from datetime import datetime
from typing import List, Dict, Any, Optional
from database.db import get_db, query_all, query_one
from models.model_store import get_anomaly_detector
from services.audit_service import AuditService

class IncidentService:
    """
    Manages threat detection correlation, incident lifecycle, analyst notes,
    and simulated response containment actions.
    """

    CRITICAL_RULES = {
        "StopLogging": ("RULE-EVASION-01", "CloudTrail Audit Logging Terminated", "CRITICAL"),
        "DeleteTrail": ("RULE-EVASION-02", "CloudTrail Trail Deleted Permanently", "CRITICAL"),
        "AttachUserPolicy": ("RULE-PRIV-01", "Privilege Escalation via AdministratorAccess Attachment", "HIGH"),
        "PutUserPolicy": ("RULE-PRIV-02", "Inline Administrator Policy Injected", "HIGH"),
        "CreateAccessKey": ("RULE-CRED-01", "Secondary Persistence via Access Key Creation", "HIGH"),
        "PutBucketPolicy": ("RULE-STORAGE-01", "Public S3 Bucket Policy Exposure", "HIGH"),
        "AuthorizeSecurityGroupIngress": ("RULE-NET-01", "Perimeter Exposure: Unrestricted Ingress (0.0.0.0/0)", "HIGH"),
        "GetSecretValue": ("RULE-DATA-01", "Sensitive Secret Credentials Accessed from Anomalous IP", "MEDIUM")
    }

    @classmethod
    def evaluate_and_create_incidents(cls, normalized_event_ids: List[int] = None) -> List[Dict[str, Any]]:
        """
        Runs ML anomaly detector and rule correlator against normalized events.
        Creates incidents for events exceeding alert thresholds or matching high-severity rules.
        """
        detector = get_anomaly_detector()

        if normalized_event_ids:
            placeholders = ",".join("?" for _ in normalized_event_ids)
            query = f"SELECT * FROM normalized_events WHERE id IN ({placeholders})"
            events = query_all(query, tuple(normalized_event_ids))
        else:
            # Evaluate events that haven't been associated with an incident yet
            events = query_all("""
                SELECT n.* FROM normalized_events n
                LEFT JOIN incidents i ON n.event_id = i.event_id
                WHERE i.id IS NULL
            """)

        new_incidents = []
        for evt in events:
            # 1. ML Detection Prediction
            ml_result = detector.predict_event(evt)
            ml_score = ml_result["anomaly_score"]
            is_ml_anomaly = ml_result["is_anomaly"]
            contributions = ml_result["contributions"]

            # 2. Rule Evaluation
            event_name = evt["event_name"]
            rule_code = None
            rule_desc = None
            rule_severity = None

            if event_name in cls.CRITICAL_RULES:
                rule_code, rule_desc, rule_severity = cls.CRITICAL_RULES[event_name]
            elif evt["is_auth_failure"] == 1:
                rule_code, rule_desc, rule_severity = ("RULE-AUTH-01", "Console Authentication Failure / Potential Brute Force", "MEDIUM")

            # 3. Determine if incident should be raised
            should_create = False
            composite_severity = "LOW"

            if rule_code is not None:
                should_create = True
                composite_severity = rule_severity
            
            if ml_score >= 0.85:
                should_create = True
                composite_severity = "CRITICAL"
            elif ml_score >= 0.70:
                should_create = True
                composite_severity = "HIGH" if composite_severity not in ("CRITICAL",) else composite_severity
            elif ml_score >= 0.50:
                should_create = True
                composite_severity = "MEDIUM" if composite_severity not in ("CRITICAL", "HIGH") else composite_severity
            elif is_ml_anomaly:
                should_create = True
                composite_severity = "LOW"

            if not should_create:
                continue

            # Format contributing factors
            factor_descriptions = [c["description"] for c in contributions]
            risk_factors_str = "; ".join(factor_descriptions) if factor_descriptions else "Statistical baseline divergence"
            if rule_desc:
                risk_factors_str = f"Rule Trigger: {rule_desc}. " + risk_factors_str

            # Fetch raw log payload for evidence
            raw_log = query_one("SELECT raw_payload FROM raw_logs WHERE event_id = ?", (evt["event_id"],))
            raw_payload_str = raw_log["raw_payload"] if raw_log else "{}"

            evidence_dict = {
                "event_id": evt["event_id"],
                "timestamp": evt["timestamp"],
                "event_name": evt["event_name"],
                "principal_id": evt["principal_id"],
                "source_ip": evt["source_ip"],
                "target_resource": evt["target_resource"],
                "ml_anomaly_score": ml_score,
                "ml_decision_score": ml_result["decision_score"],
                "feature_contributions": contributions,
                "rule_code": rule_code,
                "rule_description": rule_desc,
                "raw_event": json.loads(raw_payload_str)
            }

            # Generate unique incident code
            incident_code = f"INC-2026-{uuid.uuid4().hex[:6].upper()}"
            title = f"{composite_severity}: {rule_desc or event_name} on {evt['target_resource'] or evt['event_source']}"
            description = (
                f"Suspicious activity detected for principal '{evt['principal_id']}' executing '{event_name}' from IP '{evt['source_ip']}'. "
                f"ML Isolation Forest anomaly score: {ml_score}. Key drivers: {risk_factors_str}"
            )

            now_ts = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

            with get_db() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO incidents (
                        incident_code, event_id, title, event_name, event_time,
                        severity, ml_anomaly_score, is_ml_anomaly, rule_triggered,
                        risk_factors, principal, source_ip, status, assigned_to,
                        description, evidence_json, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    incident_code, evt["event_id"], title, event_name, evt["timestamp"],
                    composite_severity, ml_score, 1 if is_ml_anomaly else 0, rule_code or "ML-ONLY",
                    risk_factors_str, evt["principal_id"], evt["source_ip"], "Open", "Unassigned",
                    description, json.dumps(evidence_dict), now_ts, now_ts
                ))
                inc_id = cursor.lastrowid

            AuditService.log_action(
                category="THREAT_DETECTION",
                action="INCIDENT_RAISED",
                actor="CloudSentinel-DetectionEngine",
                target_id=incident_code,
                details=f"Raised {composite_severity} incident for {event_name} (ML score: {ml_score})"
            )

            new_incidents.append({
                "id": inc_id,
                "incident_code": incident_code,
                "title": title,
                "severity": composite_severity,
                "ml_anomaly_score": ml_score
            })

        return new_incidents

    @classmethod
    def get_incidents(cls, severity: str = None, status: str = None, event_name: str = None, search: str = None, limit: int = 100) -> List[Dict[str, Any]]:
        """Retrieves filtered list of incidents."""
        conditions = []
        params = []

        if severity:
            conditions.append("severity = ?")
            params.append(severity.upper())
        if status:
            conditions.append("status = ?")
            params.append(status)
        if event_name:
            conditions.append("event_name = ?")
            params.append(event_name)
        if search:
            conditions.append("(title LIKE ? OR principal LIKE ? OR source_ip LIKE ? OR incident_code LIKE ?)")
            s = f"%{search}%"
            params.extend([s, s, s, s])

        where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        query = f"""
            SELECT * FROM incidents
            {where_clause}
            ORDER BY id DESC
            LIMIT ?
        """
        params.append(limit)
        return query_all(query, tuple(params))

    @classmethod
    def get_incident_by_id(cls, incident_id: int) -> Optional[Dict[str, Any]]:
        inc = query_one("SELECT * FROM incidents WHERE id = ?", (incident_id,))
        if not inc:
            return None
        
        # Parse evidence JSON
        try:
            inc["evidence"] = json.loads(inc["evidence_json"])
        except Exception:
            inc["evidence"] = {}

        # Fetch notes
        inc["notes"] = query_all("SELECT * FROM analyst_notes WHERE incident_id = ? ORDER BY id DESC", (incident_id,))
        # Fetch actions
        inc["actions"] = query_all("SELECT * FROM response_actions WHERE incident_id = ? ORDER BY id DESC", (incident_id,))
        return inc

    @classmethod
    def update_incident_status(cls, incident_id: int, new_status: str, actor: str = "SOC_Analyst") -> bool:
        valid_statuses = {"Open", "Investigating", "Resolved", "False Positive"}
        if new_status not in valid_statuses:
            raise ValueError(f"Invalid status: {new_status}. Must be one of {valid_statuses}")

        inc = cls.get_incident_by_id(incident_id)
        if not inc:
            return False

        old_status = inc["status"]
        now_ts = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

        with get_db() as conn:
            conn.execute("""
                UPDATE incidents
                SET status = ?, updated_at = ?
                WHERE id = ?
            """, (new_status, now_ts, incident_id))

        AuditService.log_action(
            category="INCIDENT_MANAGEMENT",
            action="STATUS_CHANGED",
            actor=actor,
            target_id=inc["incident_code"],
            details=f"Status changed from '{old_status}' to '{new_status}'"
        )
        return True

    @classmethod
    def add_analyst_note(cls, incident_id: int, note_text: str, author: str = "SOC_Analyst") -> int:
        if not note_text.strip():
            raise ValueError("Note text cannot be empty.")

        now_ts = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO analyst_notes (incident_id, author, note, created_at)
                VALUES (?, ?, ?, ?)
            """, (incident_id, author, note_text.strip(), now_ts))
            note_id = cursor.lastrowid

        inc = cls.get_incident_by_id(incident_id)
        if inc:
            AuditService.log_action(
                category="INCIDENT_MANAGEMENT",
                action="NOTE_ADDED",
                actor=author,
                target_id=inc["incident_code"],
                details=f"Analyst note added: {note_text[:60]}..."
            )
        return note_id

    @classmethod
    def execute_simulated_response(cls, incident_id: int, action_type: str, actor: str = "SOC_Analyst", parameters: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Executes a safety-governed, simulated cloud response action.
        Never touches real production AWS environments without active cloud authorization.
        Records full audit trail and details.
        """
        inc = cls.get_incident_by_id(incident_id)
        if not inc:
            raise ValueError("Incident not found.")

        target_principal = inc["principal"]
        target_ip = inc["source_ip"]
        now_ts = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        params_str = json.dumps(parameters or {})

        action_catalog = {
            "REVOKE_SESSION": {
                "name": "Revoke Active IAM Session",
                "entity": target_principal,
                "details": f"[SIMULATED] Attached AWS inline policy invalidating STS tokens issued before {now_ts} for principal '{target_principal}'.",
                "aws_cli": f"aws iam put-user-policy --user-name {target_principal} --policy-name RevokeOlderSessions --policy-document <DenyBeforeTokenIssueTime>"
            },
            "QUARANTINE_ROLE": {
                "name": "Attach DenyAll Quarantine Policy",
                "entity": target_principal,
                "details": f"[SIMULATED] Attached 'AWSCompromisedKeyQuarantine' policy to isolate '{target_principal}' from all mutating API operations.",
                "aws_cli": f"aws iam attach-user-policy --user-name {target_principal} --policy-arn arn:aws:iam::aws:policy/AWSCompromisedKeyQuarantine"
            },
            "ROTATE_KEY": {
                "name": "Rotate AWS Access Key",
                "entity": target_principal,
                "details": f"[SIMULATED] Deactivated active access keys for '{target_principal}' and initialized rotation workflow.",
                "aws_cli": f"aws iam update-access-key --access-key-id <KEY_ID> --status Inactive --user-name {target_principal}"
            },
            "ISOLATE_IP": {
                "name": "Isolate Attacking IP (NACL Deny)",
                "entity": target_ip,
                "details": f"[SIMULATED] Added rule 50 to VPC Network ACL denying inbound traffic from '{target_ip}' across all subnets.",
                "aws_cli": f"aws ec2 create-network-acl-entry --network-acl-id acl-0123 --ingress --rule-number 50 --protocol -1 --cidr-block {target_ip}/32 --rule-action deny"
            },
            "RESTORE_LOGGING": {
                "name": "Restart CloudTrail Audit Logging",
                "entity": "CloudTrail",
                "details": f"[SIMULATED] Re-enabled CloudTrail multi-region logging for '{inc.get('target_resource') or inc.get('evidence', {}).get('target_resource') or 'organization-audit-trail'}'.",
                "aws_cli": "aws cloudtrail start-logging --name organization-audit-trail"
            }
        }

        if action_type not in action_catalog:
            raise ValueError(f"Unknown action type: {action_type}. Supported: {list(action_catalog.keys())}")

        action_meta = action_catalog[action_type]

        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO response_actions (
                    incident_id, action_name, target_entity, action_type,
                    status, performed_by, parameters, details, timestamp
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                incident_id, action_meta["name"], action_meta["entity"], action_type,
                "Simulated (Verified)", actor, params_str, action_meta["details"], now_ts
            ))
            action_id = cursor.lastrowid

        AuditService.log_action(
            category="AUTONOMOUS_RESPONSE",
            action=action_type,
            actor=actor,
            target_id=inc["incident_code"],
            details=action_meta["details"]
        )

        return {
            "action_id": action_id,
            "incident_code": inc["incident_code"],
            "action_name": action_meta["name"],
            "status": "Simulated (Verified Safe)",
            "execution_mode": "Demonstration Simulation (No production credentials modified)",
            "details": action_meta["details"],
            "recommended_aws_command": action_meta["aws_cli"],
            "timestamp": now_ts
        }
