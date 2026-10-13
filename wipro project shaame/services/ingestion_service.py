import json
from typing import Dict, Any, List, Tuple
from pipelines.log_parser import CloudTrailLogParser, LogParseError
from pipelines.pandas_pipeline import PandasETLPipeline
from services.incident_service import IncidentService
from models.model_store import get_anomaly_detector
from database.db import query_all

class IngestionService:
    """
    Coordinates end-to-end ingestion:
    Validates logs -> Runs Pandas ETL -> Evaluates ML/Rule Threats -> Creates Incidents
    """

    @classmethod
    def ingest_file_content(cls, content: str, filename: str, source_type: str = "upload") -> Dict[str, Any]:
        """Processes raw file content from file upload or demonstration sample."""
        try:
            valid_records, rejected_records = CloudTrailLogParser.parse_content(content, filename=filename)
        except LogParseError as e:
            return {
                "success": False,
                "error": str(e),
                "total_records": 0,
                "processed_records": 0,
                "rejected_records": 1,
                "duplicate_records": 0,
                "incidents_raised": 0
            }

        # Run Pandas ETL pipeline
        etl_summary = PandasETLPipeline.run(
            valid_records=valid_records,
            rejected_count=len(rejected_records),
            source_type=source_type,
            filename=filename
        )

        # Train ML model if not yet trained and we have data
        detector = get_anomaly_detector()
        if detector.model is None:
            all_norm_events = query_all("SELECT * FROM normalized_events LIMIT 500")
            if len(all_norm_events) >= 5:
                detector.train(all_norm_events)

        # Correlate threats and create incidents
        new_incidents = IncidentService.evaluate_and_create_incidents()

        return {
            "success": True,
            "etl_summary": etl_summary,
            "rejected_details": rejected_records[:10],
            "incidents_raised": len(new_incidents),
            "new_incidents": new_incidents
        }

    @classmethod
    def ingest_single_event(cls, event_dict: Dict[str, Any]) -> Dict[str, Any]:
        """Ingests a single CloudTrail-style event from REST API."""
        try:
            val_err = CloudTrailLogParser._validate_single_record(event_dict)
            if val_err:
                return {"success": False, "error": val_err}

            normalized_dict = CloudTrailLogParser._normalize_raw_dict(event_dict)
            etl_summary = PandasETLPipeline.run(
                valid_records=[normalized_dict],
                rejected_count=0,
                source_type="api_stream",
                filename="stream_event"
            )

            # Correlate threats
            new_incidents = IncidentService.evaluate_and_create_incidents()

            return {
                "success": True,
                "etl_summary": etl_summary,
                "incidents_raised": len(new_incidents),
                "new_incidents": new_incidents
            }
        except Exception as e:
            return {"success": False, "error": str(e)}
