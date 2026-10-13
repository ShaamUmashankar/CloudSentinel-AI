import json
import csv
import io
import re
from datetime import datetime
from typing import List, Dict, Tuple, Any

class LogParseError(Exception):
    pass

class CloudTrailLogParser:
    """
    Validates and parses CloudTrail-style logs from JSON or CSV payloads.
    Provides clear error messages for malformed records and enforces schema rules.
    """

    ISO_TIMESTAMP_REGEX = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?$")

    @classmethod
    def validate_timestamp(cls, ts_str: str) -> bool:
        if not ts_str or not isinstance(ts_str, str):
            return False
        return bool(cls.ISO_TIMESTAMP_REGEX.match(ts_str.strip()))

    @classmethod
    def parse_content(cls, content: str, filename: str = "") -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """
        Parses raw string content into valid and rejected records.
        Returns: (valid_records, rejected_records)
        """
        content = content.strip()
        if not content:
            raise LogParseError("Log content is empty.")

        is_json = False
        if filename.endswith(".json") or content.startswith("{") or content.startswith("["):
            is_json = True

        if is_json:
            return cls._parse_json(content)
        else:
            return cls._parse_csv(content)

    @classmethod
    def _parse_json(cls, content: str) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        try:
            data = json.loads(content)
        except json.JSONDecodeError as e:
            raise LogParseError(f"Invalid JSON syntax: {str(e)}")

        records_raw = []
        if isinstance(data, dict):
            if "Records" in data and isinstance(data["Records"], list):
                records_raw = data["Records"]
            else:
                # Single event JSON
                records_raw = [data]
        elif isinstance(data, list):
            records_raw = data
        else:
            raise LogParseError("JSON root must be an object with 'Records' array, a JSON array of events, or a single event.")

        valid = []
        rejected = []

        for idx, rec in enumerate(records_raw):
            if not isinstance(rec, dict):
                rejected.append({"index": idx, "reason": "Record is not a valid JSON object", "raw": str(rec)})
                continue

            val_err = cls._validate_single_record(rec)
            if val_err:
                rejected.append({"index": idx, "reason": val_err, "raw": rec})
            else:
                valid.append(cls._normalize_raw_dict(rec))

        return valid, rejected

    @classmethod
    def _parse_csv(cls, content: str) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        valid = []
        rejected = []
        f = io.StringIO(content)
        reader = csv.DictReader(f)

        if not reader.fieldnames:
            raise LogParseError("CSV file has no header row.")

        header_set = set(col.strip().lower() for col in reader.fieldnames)
        required = {"eventname", "eventsource"}
        if not required.issubset(header_set):
            raise LogParseError(f"CSV missing mandatory headers: {required - header_set}. Found: {reader.fieldnames}")

        for idx, row in enumerate(reader):
            # Map CSV row to CloudTrail structure
            rec = {
                "eventID": row.get("eventID") or row.get("eventId") or f"csv-evt-{idx}",
                "eventTime": row.get("eventTime") or row.get("timestamp") or datetime.utcnow().isoformat() + "Z",
                "eventName": row.get("eventName") or row.get("event_name", ""),
                "eventSource": row.get("eventSource") or row.get("event_source", ""),
                "awsRegion": row.get("awsRegion") or row.get("region", "us-east-1"),
                "sourceIPAddress": row.get("sourceIPAddress") or row.get("source_ip", "0.0.0.0"),
                "userAgent": row.get("userAgent") or row.get("user_agent", "CSV-Import"),
                "errorCode": row.get("errorCode") or None,
                "errorMessage": row.get("errorMessage") or None,
                "userIdentity": {
                    "type": row.get("userType") or "IAMUser",
                    "userName": row.get("userName") or row.get("principal", "unknown_user"),
                    "principalId": row.get("userName") or "unknown_id"
                },
                "requestParameters": row.get("requestParameters") or None,
                "responseElements": row.get("responseElements") or None
            }

            val_err = cls._validate_single_record(rec)
            if val_err:
                rejected.append({"index": idx, "reason": val_err, "raw": row})
            else:
                valid.append(cls._normalize_raw_dict(rec))

        return valid, rejected

    @classmethod
    def _validate_single_record(cls, rec: Dict[str, Any]) -> str:
        if not rec.get("eventName"):
            return "Missing mandatory 'eventName' attribute"
        if not rec.get("eventSource"):
            return "Missing mandatory 'eventSource' attribute"
        
        # Validate eventTime
        ts = rec.get("eventTime")
        if not ts:
            return "Missing 'eventTime' timestamp"
        if not cls.validate_timestamp(ts):
            return f"Malformed timestamp format '{ts}'. Expected ISO-8601 (YYYY-MM-DDTHH:MM:SSZ)"

        return ""

    @classmethod
    def _normalize_raw_dict(cls, rec: Dict[str, Any]) -> Dict[str, Any]:
        """Ensures all expected root keys exist with appropriate fallbacks."""
        user_identity = rec.get("userIdentity") or {}
        if isinstance(user_identity, str):
            try:
                user_identity = json.loads(user_identity)
            except Exception:
                user_identity = {"userName": user_identity}

        user_name = user_identity.get("userName") or user_identity.get("principalId") or "unknown_principal"
        user_type = user_identity.get("type") or "IAMUser"

        return {
            "event_id": str(rec.get("eventID") or f"evt-{hash(json.dumps(rec, sort_keys=True))}"),
            "event_time": str(rec.get("eventTime")),
            "event_name": str(rec.get("eventName")),
            "event_source": str(rec.get("eventSource")),
            "aws_region": str(rec.get("awsRegion") or "us-east-1"),
            "source_ip": str(rec.get("sourceIPAddress") or "127.0.0.1"),
            "user_identity": json.dumps(user_identity),
            "user_name": str(user_name),
            "user_type": str(user_type),
            "user_agent": str(rec.get("userAgent") or "unknown"),
            "error_code": rec.get("errorCode"),
            "error_message": rec.get("errorMessage"),
            "request_parameters": json.dumps(rec.get("requestParameters")) if rec.get("requestParameters") else None,
            "response_elements": json.dumps(rec.get("responseElements")) if rec.get("responseElements") else None,
            "raw_payload": json.dumps(rec)
        }
