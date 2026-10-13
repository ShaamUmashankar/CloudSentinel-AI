import time
import ipaddress
import uuid
import json
import pandas as pd
from datetime import datetime
from typing import List, Dict, Any, Tuple
from database.db import get_db, query_all

class PandasETLPipeline:
    """
    Data Engineering pipeline using Pandas for cleaning, normalization,
    deduplication, feature extraction, and database persistence.
    """

    PRIVILEGE_ACTIONS = {
        "AttachUserPolicy", "AttachRolePolicy", "PutUserPolicy", "PutRolePolicy",
        "CreateAccessKey", "CreateLoginProfile", "UpdateLoginProfile", "AssumeRole",
        "AddUserToGroup", "CreatePolicyVersion", "SetDefaultPolicyVersion"
    }

    TAMPERING_ACTIONS = {
        "StopLogging", "DeleteTrail", "UpdateTrail", "PutEventSelectors",
        "DeleteFlowLogs", "DisableAlarm", "DeleteDetector", "ArchiveFindings"
    }

    EXPOSURE_ACTIONS = {
        "PutBucketPolicy", "PutBucketAcl", "AuthorizeSecurityGroupIngress",
        "ModifySecurityGroupRules", "PutKeyPolicy", "DeleteBucketPolicy"
    }

    DATA_ACCESS_ACTIONS = {
        "GetObject", "ListObjects", "GetSecretValue", "BatchGetSecretValue",
        "GetItem", "Scan", "Query", "DescribeKey"
    }

    @staticmethod
    def is_private_ip(ip_str: str) -> bool:
        try:
            ip = ipaddress.ip_address(ip_str.strip())
            return (
                ip in ipaddress.ip_network("10.0.0.0/8") or
                ip in ipaddress.ip_network("172.16.0.0/12") or
                ip in ipaddress.ip_network("192.168.0.0/16") or
                ip.is_loopback
            )
        except ValueError:
            return False

    @classmethod
    def categorize_event(cls, event_name: str, event_source: str) -> str:
        if "signin" in event_source or event_name == "ConsoleLogin":
            return "Authentication"
        if event_name in cls.TAMPERING_ACTIONS or "cloudtrail" in event_source:
            return "Defense_Evasion"
        if event_name in cls.PRIVILEGE_ACTIONS or "iam" in event_source:
            return "IAM_Privilege"
        if event_name in cls.EXPOSURE_ACTIONS:
            return "Network_Perimeter" if "ec2" in event_source else "Data_Access"
        if event_name in cls.DATA_ACCESS_ACTIONS or "s3" in event_source or "secretsmanager" in event_source:
            return "Data_Access"
        return "Infrastructure_Read"

    @classmethod
    def calculate_base_rule_risk(cls, row: Dict[str, Any]) -> float:
        risk = 0.1
        event_name = row.get("event_name", "")
        source_ip = row.get("source_ip", "")
        is_internal = cls.is_private_ip(source_ip)
        has_error = bool(row.get("error_code"))

        if event_name in cls.TAMPERING_ACTIONS:
            risk += 0.8
        if event_name in cls.PRIVILEGE_ACTIONS:
            risk += 0.6 if not is_internal else 0.4
        if event_name == "ConsoleLogin" and has_error:
            risk += 0.65
        if event_name in cls.EXPOSURE_ACTIONS:
            risk += 0.7
        if not is_internal:
            risk += 0.15
        if has_error:
            risk += 0.1

        return min(round(risk, 2), 1.0)

    @classmethod
    def run(cls, valid_records: List[Dict[str, Any]], rejected_count: int = 0, source_type: str = "upload", filename: str = "batch") -> Dict[str, Any]:
        """
        Executes the ETL pipeline:
        1. Loads into Pandas DataFrame
        2. Deduplicates against existing database eventIDs and batch duplicates
        3. Cleans and normalizes fields
        4. Extracts security feature flags
        5. Persists raw_logs and normalized_events
        6. Returns detailed ETL summary
        """
        start_time = time.time()
        batch_id = str(uuid.uuid4())
        total_input = len(valid_records) + rejected_count

        if not valid_records:
            etl_summary = {
                "run_id": batch_id,
                "source_type": source_type,
                "filename": filename,
                "total_records": total_input,
                "processed_records": 0,
                "duplicate_records": 0,
                "rejected_records": rejected_count,
                "duration_seconds": round(time.time() - start_time, 4),
                "status": "COMPLETED_EMPTY"
            }
            cls._record_etl_run(etl_summary)
            return etl_summary

        df = pd.DataFrame(valid_records)

        # 1. Deduplicate within current batch
        initial_count = len(df)
        df = df.drop_duplicates(subset=["event_id"], keep="first")
        batch_dupes = initial_count - len(df)

        # 2. Check for existing event_ids in database
        existing_event_ids = set()
        existing_rows = query_all("SELECT event_id FROM raw_logs")
        for r in existing_rows:
            existing_event_ids.add(r["event_id"])

        # Filter out duplicates already in DB
        mask_existing = df["event_id"].isin(existing_event_ids)
        db_dupes = int(mask_existing.sum())
        duplicate_records = batch_dupes + db_dupes

        df_clean = df[~mask_existing].copy()

        if df_clean.empty:
            etl_summary = {
                "run_id": batch_id,
                "source_type": source_type,
                "filename": filename,
                "total_records": total_input,
                "processed_records": 0,
                "duplicate_records": duplicate_records,
                "rejected_records": rejected_count,
                "duration_seconds": round(time.time() - start_time, 4),
                "status": "COMPLETED_ALL_DUPLICATES"
            }
            cls._record_etl_run(etl_summary)
            return etl_summary

        # 3. Clean and normalize fields
        df_clean["event_time"] = pd.to_datetime(df_clean["event_time"], errors="coerce", utc=True).dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        df_clean["source_ip"] = df_clean["source_ip"].fillna("127.0.0.1").astype(str)
        df_clean["is_internal_ip"] = df_clean["source_ip"].apply(lambda ip: 1 if cls.is_private_ip(ip) else 0)
        df_clean["is_error"] = df_clean["error_code"].apply(lambda ec: 1 if pd.notna(ec) and ec else 0)
        df_clean["event_category"] = df_clean.apply(lambda row: cls.categorize_event(row["event_name"], row["event_source"]), axis=1)

        # Feature Flags
        df_clean["is_privilege_related"] = df_clean["event_name"].apply(lambda en: 1 if en in cls.PRIVILEGE_ACTIONS else 0)
        df_clean["is_auth_failure"] = df_clean.apply(lambda r: 1 if r["event_name"] == "ConsoleLogin" and r["is_error"] == 1 else 0, axis=1)
        df_clean["is_tampering"] = df_clean["event_name"].apply(lambda en: 1 if en in cls.TAMPERING_ACTIONS else 0)
        df_clean["risk_score"] = df_clean.apply(lambda r: cls.calculate_base_rule_risk(r.to_dict()), axis=1)

        # Derive target resource
        def extract_target_resource(row):
            req_params = row.get("request_parameters")
            if req_params and isinstance(req_params, str):
                try:
                    params_dict = json.loads(req_params)
                    return (
                        params_dict.get("userName") or
                        params_dict.get("bucketName") or
                        params_dict.get("name") or
                        params_dict.get("groupId") or
                        params_dict.get("secretId") or
                        params_dict.get("keyId") or
                        row["event_source"]
                    )
                except Exception:
                    pass
            return row["event_source"]

        df_clean["target_resource"] = df_clean.apply(extract_target_resource, axis=1)
        df_clean["action_type"] = df_clean["event_name"].apply(lambda x: "Write" if any(x.startswith(p) for p in ["Create", "Put", "Delete", "Attach", "Stop", "Modify", "Authorize"]) else "Read")

        # 4. Insert into database
        ingested_at = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        with get_db() as conn:
            for _, row in df_clean.iterrows():
                # Insert raw log
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO raw_logs (
                        event_id, event_time, event_name, event_source, aws_region,
                        source_ip, user_identity, user_name, user_type, user_agent,
                        error_code, error_message, request_parameters, response_elements,
                        raw_payload, batch_id, ingested_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    row["event_id"], row["event_time"], row["event_name"], row["event_source"], row["aws_region"],
                    row["source_ip"], row["user_identity"], row["user_name"], row["user_type"], row["user_agent"],
                    row["error_code"], row["error_message"], row["request_parameters"], row["response_elements"],
                    row["raw_payload"], batch_id, ingested_at
                ))
                raw_id = cursor.lastrowid

                # Insert normalized event
                conn.execute("""
                    INSERT INTO normalized_events (
                        raw_log_id, event_id, timestamp, event_name, event_category,
                        event_source, principal_id, principal_type, source_ip, is_internal_ip,
                        is_error, error_code, target_resource, action_type, risk_score,
                        is_privilege_related, is_auth_failure, is_tampering
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    raw_id, row["event_id"], row["event_time"], row["event_name"], row["event_category"],
                    row["event_source"], row["user_name"], row["user_type"], row["source_ip"], int(row["is_internal_ip"]),
                    int(row["is_error"]), row["error_code"], row["target_resource"], row["action_type"], float(row["risk_score"]),
                    int(row["is_privilege_related"]), int(row["is_auth_failure"]), int(row["is_tampering"])
                ))

        processed_count = len(df_clean)
        duration = round(time.time() - start_time, 4)

        etl_summary = {
            "run_id": batch_id,
            "source_type": source_type,
            "filename": filename,
            "total_records": total_input,
            "processed_records": processed_count,
            "duplicate_records": duplicate_records,
            "rejected_records": rejected_count,
            "duration_seconds": duration,
            "status": "SUCCESS"
        }
        cls._record_etl_run(etl_summary)
        return etl_summary

    @classmethod
    def _record_etl_run(cls, summary: Dict[str, Any]):
        try:
            with get_db() as conn:
                conn.execute("""
                    INSERT INTO etl_runs (
                        run_id, source_type, filename, total_records, processed_records,
                        duplicate_records, rejected_records, duration_seconds, status, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
                """, (
                    summary["run_id"], summary["source_type"], summary["filename"],
                    summary["total_records"], summary["processed_records"], summary["duplicate_records"],
                    summary["rejected_records"], summary["duration_seconds"], summary["status"]
                ))
        except Exception as e:
            print(f"[ETL Warning] Could not record ETL run: {e}")
