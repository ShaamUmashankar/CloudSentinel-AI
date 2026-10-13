from flask import Blueprint, render_template, abort
from database.db import query_all, query_one
from services.incident_service import IncidentService
from models.model_store import get_anomaly_detector
from services.rag_service import RAGSecurityAssistant
from pipelines.pyspark_pipeline import PySparkPipelineManager
from config.config import Config

web_bp = Blueprint("web", __name__)

@web_bp.route("/")
def home():
    """1. Home & System Overview."""
    stats = {
        "events": query_one("SELECT COUNT(*) as c FROM normalized_events")["c"],
        "incidents": query_one("SELECT COUNT(*) as c FROM incidents")["c"],
        "kb_docs": query_one("SELECT COUNT(*) as c FROM knowledge_docs")["c"]
    }
    return render_template("index.html", stats=stats, config=Config)

@web_bp.route("/dashboard")
def dashboard():
    """2. Security Dashboard."""
    return render_template("dashboard.html", config=Config)

@web_bp.route("/ingestion")
def ingestion():
    """3. Log Upload and Ingestion."""
    etl_history = query_all("SELECT * FROM etl_runs ORDER BY id DESC LIMIT 10")
    return render_template("ingestion.html", etl_history=etl_history, config=Config)

@web_bp.route("/events")
def events():
    """4. Event Explorer."""
    event_list = query_all("SELECT * FROM normalized_events ORDER BY id DESC LIMIT 100")
    categories = query_all("SELECT DISTINCT event_category FROM normalized_events")
    return render_template("events.html", events=event_list, categories=[c["event_category"] for c in categories], config=Config)

@web_bp.route("/threats")
def threats():
    """5. Threat and Anomaly List."""
    incidents = query_all("SELECT * FROM incidents ORDER BY id DESC")
    return render_template("threats.html", incidents=incidents, config=Config)

@web_bp.route("/incident/<int:incident_id>")
def incident_detail(incident_id):
    """6. Incident Details."""
    inc = IncidentService.get_incident_by_id(incident_id)
    if not inc:
        abort(404)
    return render_template("incident_detail.html", incident=inc, config=Config)

@web_bp.route("/assistant")
def assistant():
    """7. GenAI Security Assistant."""
    incidents = query_all("SELECT id, incident_code, title, severity, event_name FROM incidents ORDER BY id DESC")
    rag = RAGSecurityAssistant()
    return render_template("assistant.html", incidents=incidents, rag_status=rag.get_status(), config=Config)

@web_bp.route("/incident-mgmt")
def incident_mgmt():
    """8. Incident Management Queue."""
    incidents = query_all("SELECT * FROM incidents ORDER BY id DESC")
    return render_template("incident_mgmt.html", incidents=incidents, config=Config)

@web_bp.route("/knowledge-base")
def knowledge_base():
    """9. Knowledge-Base Management."""
    docs = query_all("SELECT * FROM knowledge_docs ORDER BY id ASC")
    rag = RAGSecurityAssistant()
    return render_template("knowledge_base.html", docs=docs, rag_status=rag.get_status(), config=Config)

@web_bp.route("/system-config")
def system_config():
    """10. System Configuration & Model Status."""
    detector = get_anomaly_detector()
    glue_status = PySparkPipelineManager.get_pipeline_status()
    rag = RAGSecurityAssistant()
    settings = query_all("SELECT * FROM system_settings")
    audit_logs = query_all("SELECT * FROM audit_trail ORDER BY id DESC LIMIT 20")
    return render_template("system_config.html",
                           detector_status=detector.get_status(),
                           glue_status=glue_status,
                           rag_status=rag.get_status(),
                           settings=settings,
                           audit_logs=audit_logs,
                           config=Config)
