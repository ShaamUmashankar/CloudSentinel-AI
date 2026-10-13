import os
from pathlib import Path
from flask import Flask, render_template
from config.config import Config
from database.db import init_db, query_one
from routes.api_routes import api_bp
from routes.web_routes import web_bp
from services.rag_service import RAGSecurityAssistant
from services.ingestion_service import IngestionService
from models.model_store import get_anomaly_detector

def create_app(config_class=Config):
    """Application factory for CloudSentinel AI."""
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Register Blueprints
    app.register_blueprint(api_bp)
    app.register_blueprint(web_bp)

    # Error Handlers
    @app.errorhandler(404)
    def not_found_error(error):
        return render_template("base.html"), 404

    @app.errorhandler(500)
    def internal_error(error):
        return render_template("base.html"), 500

    # Initialize Core Subsystems
    with app.app_context():
        # 1. Initialize SQLite Database
        init_db()

        # 2. Build or load FAISS Knowledge Base Index
        rag = RAGSecurityAssistant()
        rag.load_or_build_index()

        # 3. Seed demonstration logs if database is empty
        event_count = query_one("SELECT COUNT(*) as cnt FROM normalized_events")
        if not event_count or event_count["cnt"] == 0:
            sample_path = Path(Config.BASE_DIR) / "data" / "sample_logs" / "cloudtrail_synthetic_mixed.json"
            if sample_path.exists():
                print("[Bootstrap] Ingesting initial synthetic CloudTrail demonstration logs...")
                with open(sample_path, "r", encoding="utf-8") as f:
                    content = f.read()
                IngestionService.ingest_file_content(content, filename=sample_path.name, source_type="bootstrap")
                print("[Bootstrap] Database seeded and ML detector initialized.")

        # 4. Verify ML Anomaly Detector
        detector = get_anomaly_detector()
        print(f"[Bootstrap] CloudSentinel AI online. ML Model Ready: {detector.get_status()['is_ready']}")

    return app

app = create_app()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("DEBUG", "True").lower() in ("true", "1")
    print(f"[*] Starting CloudSentinel AI on http://127.0.0.1:{port}")
    app.run(host="0.0.0.0", port=port, debug=debug)
