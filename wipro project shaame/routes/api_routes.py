import json
from flask import Blueprint, request, jsonify
from services.ingestion_service import IngestionService
from services.incident_service import IncidentService
from services.rag_service import RAGSecurityAssistant
from services.audit_service import AuditService
from models.model_store import get_anomaly_detector
from pipelines.pyspark_pipeline import PySparkPipelineManager
from database.db import query_all, query_one, get_db
from config.config import Config

api_bp = Blueprint("api", __name__, url_prefix="/api")

@api_bp.route("/dashboard/stats", methods=["GET"])
def get_dashboard_stats():
    """Returns dynamic KPI metrics, severity breakdowns, and threat trends from SQLite."""
    # Total events
    total_events_res = query_one("SELECT COUNT(*) as cnt FROM normalized_events")
    total_events = total_events_res["cnt"] if total_events_res else 0

    # Total anomalies detected
    total_anomalies_res = query_one("SELECT COUNT(*) as cnt FROM incidents")
    total_anomalies = total_anomalies_res["cnt"] if total_anomalies_res else 0

    # Severity counts
    sev_rows = query_all("SELECT severity, COUNT(*) as cnt FROM incidents GROUP BY severity")
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for r in sev_rows:
        severity_counts[r["severity"]] = r["cnt"]

    # Incident status counts
    status_rows = query_all("SELECT status, COUNT(*) as cnt FROM incidents GROUP BY status")
    status_counts = {"Open": 0, "Investigating": 0, "Resolved": 0, "False Positive": 0}
    for r in status_rows:
        status_counts[r["status"]] = r["cnt"]

    # Recent suspicious activities
    recent_incidents = query_all("""
        SELECT id, incident_code, title, severity, ml_anomaly_score, principal, source_ip, status, event_time
        FROM incidents
        ORDER BY id DESC
        LIMIT 6
    """)

    # Top suspicious event categories
    cat_rows = query_all("""
        SELECT event_category, COUNT(*) as cnt
        FROM normalized_events
        WHERE risk_score > 0.4 OR is_tampering = 1 OR is_privilege_related = 1
        GROUP BY event_category
        ORDER BY cnt DESC
        LIMIT 5
    """)
    top_categories = [{"category": r["event_category"], "count": r["cnt"]} for r in cat_rows]

    # Event trends by hour/date
    trend_rows = query_all("""
        SELECT substr(timestamp, 1, 13) as time_slot, COUNT(*) as total,
               SUM(CASE WHEN is_tampering = 1 OR is_privilege_related = 1 OR is_auth_failure = 1 THEN 1 ELSE 0 END) as anomalies
        FROM normalized_events
        GROUP BY time_slot
        ORDER BY time_slot DESC
        LIMIT 10
    """)
    trends = list(reversed(trend_rows))

    # Pipeline status
    last_etl = query_one("SELECT * FROM etl_runs ORDER BY id DESC LIMIT 1")
    detector = get_anomaly_detector()

    return jsonify({
        "success": True,
        "total_events": total_events,
        "total_anomalies": total_anomalies,
        "severity_counts": severity_counts,
        "status_counts": status_counts,
        "recent_incidents": recent_incidents,
        "top_categories": top_categories,
        "trends": trends,
        "etl_status": {
            "last_run": last_etl,
            "engine": "Pandas Local Pipeline (Active)",
            "glue_pyspark_available": PySparkPipelineManager.get_pipeline_status()["pyspark_installed"]
        },
        "model_status": detector.get_status()
    })

@api_bp.route("/logs/upload", methods=["POST"])
def upload_logs():
    """Handles log file upload via multipart/form-data."""
    if "file" not in request.files:
        return jsonify({"success": False, "error": "No file part in the request"}), 400

    file = request.files["file"]
    if file.filename == "":
        return jsonify({"success": False, "error": "No selected file"}), 400

    content = file.read().decode("utf-8", errors="replace")
    result = IngestionService.ingest_file_content(content, filename=file.filename, source_type="upload")
    return jsonify(result)

@api_bp.route("/logs/sample-load", methods=["POST"])
def load_sample_logs():
    """Loads curated synthetic CloudTrail sample logs for quick demonstration."""
    from pathlib import Path
    sample_file = Path(Config.BASE_DIR) / "data" / "sample_logs" / "cloudtrail_synthetic_mixed.json"
    if not sample_file.exists():
        return jsonify({"success": False, "error": "Sample file not found"}), 404

    with open(sample_file, "r", encoding="utf-8") as f:
        content = f.read()

    result = IngestionService.ingest_file_content(content, filename=sample_file.name, source_type="sample_loader")
    return jsonify(result)

@api_bp.route("/logs/ingest", methods=["POST"])
def ingest_single_event():
    """API endpoint for direct programmatic log ingestion."""
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"success": False, "error": "Request body must be valid JSON"}), 400

    result = IngestionService.ingest_single_event(data)
    return jsonify(result)

@api_bp.route("/events", methods=["GET"])
def get_events():
    """Returns normalized events with search and filters."""
    category = request.args.get("category")
    event_name = request.args.get("eventName")
    search = request.args.get("search")
    limit = int(request.args.get("limit", 100))

    conditions = []
    params = []
    if category:
        conditions.append("event_category = ?")
        params.append(category)
    if event_name:
        conditions.append("event_name = ?")
        params.append(event_name)
    if search:
        conditions.append("(event_name LIKE ? OR principal_id LIKE ? OR source_ip LIKE ?)")
        s = f"%{search}%"
        params.extend([s, s, s])

    where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
    query = f"SELECT * FROM normalized_events {where} ORDER BY id DESC LIMIT ?"
    params.append(limit)

    rows = query_all(query, tuple(params))
    return jsonify({"success": True, "count": len(rows), "events": rows})

@api_bp.route("/incidents", methods=["GET"])
def get_incidents():
    """Returns list of detected incidents."""
    severity = request.args.get("severity")
    status = request.args.get("status")
    event_name = request.args.get("eventName")
    search = request.args.get("search")
    limit = int(request.args.get("limit", 100))

    incidents = IncidentService.get_incidents(
        severity=severity, status=status, event_name=event_name, search=search, limit=limit
    )
    return jsonify({"success": True, "count": len(incidents), "incidents": incidents})

@api_bp.route("/incidents/<int:incident_id>", methods=["GET"])
def get_incident_detail(incident_id):
    """Returns single incident with full evidence and notes."""
    inc = IncidentService.get_incident_by_id(incident_id)
    if not inc:
        return jsonify({"success": False, "error": "Incident not found"}), 404
    return jsonify({"success": True, "incident": inc})

@api_bp.route("/incidents/<int:incident_id>/status", methods=["POST"])
def update_status(incident_id):
    """Updates incident status (Open, Investigating, Resolved, False Positive)."""
    data = request.get_json(silent=True) or {}
    new_status = data.get("status")
    actor = data.get("actor", "SOC_Analyst")

    try:
        updated = IncidentService.update_incident_status(incident_id, new_status, actor=actor)
        return jsonify({"success": updated, "status": new_status})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400

@api_bp.route("/incidents/<int:incident_id>/notes", methods=["POST"])
def add_note(incident_id):
    """Adds analyst note to incident history."""
    data = request.get_json(silent=True) or {}
    note_text = data.get("note", "")
    author = data.get("author", "SOC_Analyst")

    try:
        note_id = IncidentService.add_analyst_note(incident_id, note_text, author=author)
        return jsonify({"success": True, "note_id": note_id})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400

@api_bp.route("/incidents/<int:incident_id>/remediate", methods=["POST"])
def remediate_incident(incident_id):
    """Executes simulated containment action."""
    data = request.get_json(silent=True) or {}
    action_type = data.get("action_type")
    actor = data.get("actor", "SOC_Analyst")
    params = data.get("parameters", {})

    try:
        result = IncidentService.execute_simulated_response(incident_id, action_type, actor=actor, parameters=params)
        return jsonify({"success": True, "response": result})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400

@api_bp.route("/assistant/analyze", methods=["POST"])
def assistant_analyze():
    """RAG Security Assistant endpoint."""
    data = request.get_json(silent=True) or {}
    incident_id = data.get("incident_id")
    user_query = data.get("query")

    if not incident_id:
        return jsonify({"success": False, "error": "incident_id is required"}), 400

    inc = IncidentService.get_incident_by_id(int(incident_id))
    if not inc:
        return jsonify({"success": False, "error": "Incident not found"}), 404

    assistant = RAGSecurityAssistant()
    analysis = assistant.analyze_incident(inc, user_question=user_query)
    return jsonify({"success": True, "analysis": analysis})

@api_bp.route("/model/retrain", methods=["POST"])
def retrain_model():
    """Retrains the Isolation Forest model on normalized events."""
    events = query_all("SELECT * FROM normalized_events LIMIT 1000")
    detector = get_anomaly_detector()
    meta = detector.train(events)
    
    # Re-evaluate all events
    incidents = IncidentService.evaluate_and_create_incidents()
    return jsonify({
        "success": True,
        "metadata": meta,
        "new_incidents_count": len(incidents)
    })

@api_bp.route("/model/status", methods=["GET"])
def get_model_status():
    detector = get_anomaly_detector()
    return jsonify({"success": True, "status": detector.get_status()})

@api_bp.route("/system/audit", methods=["GET"])
def get_audit():
    limit = int(request.args.get("limit", 50))
    logs = AuditService.get_recent_logs(limit=limit)
    return jsonify({"success": True, "audit_trail": logs})

@api_bp.route("/knowledge-base", methods=["GET"])
def get_knowledge_base():
    docs = query_all("SELECT * FROM knowledge_docs ORDER BY id ASC")
    assistant = RAGSecurityAssistant()
    return jsonify({
        "success": True,
        "docs": docs,
        "rag_status": assistant.get_status()
    })

@api_bp.route("/knowledge-base/reindex", methods=["POST"])
def reindex_knowledge_base():
    assistant = RAGSecurityAssistant()
    res = assistant.build_index_from_disk()
    return jsonify({"success": True, "result": res})
