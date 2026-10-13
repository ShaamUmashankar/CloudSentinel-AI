# CloudSentinel AI: Intelligent Cloud Threat Detection and Autonomous Incident Response Using Generative AI

[![Python 3.11](https://img.shields.io/badge/python-3.11-blue.svg)](https://www.python.org/downloads/)
[![Flask](https://img.shields.io/badge/Flask-3.0.0-green.svg)](https://flask.palletsprojects.com/)
[![Scikit-Learn](https://img.shields.io/badge/ML-Isolation_Forest-orange.svg)](https://scikit-learn.org/)
[![FAISS](https://img.shields.io/badge/Vector_DB-FAISS-blueviolet.svg)](https://github.com/facebookresearch/faiss)
[![Tests Passing](https://img.shields.io/badge/tests-24%20passed-brightgreen.svg)](tests/)

---

## 1. Project Overview & Objective

**CloudSentinel AI** is a cloud security operations platform that collects AWS CloudTrail audit logs, cleanses and normalizes the telemetry through an automated Data Engineering ETL pipeline, detects anomalous attacker behaviors using unsupervised Machine Learning (Isolation Forest), and uses a Retrieval-Augmented Generation (RAG) AI assistant to explain security threats and recommend remediation actions.

The project demonstrates the integration of four core technical domains:
- **Cloud Engineering**: CloudTrail log ingestion, least-privilege IAM policies, and assisted incident containment simulations.
- **Data Engineering**: Robust Pandas and PySpark Glue ETL pipeline for normalization, timestamp standardization, deduplication, and feature extraction.
- **Machine Learning**: Scikit-learn Isolation Forest anomaly detector with continuous scoring and explainable SHAP-like feature attributions.
- **Generative AI**: Retrieval-Augmented Generation (RAG) assistant leveraging a local FAISS vector index over curated AWS security playbooks and MITRE ATT&CK mappings, supporting Google Gemini, OpenAI, or a transparent Fallback Demonstration Mode.

---

## 2. Technology Stack

- **Frontend**: HTML5, Vanilla CSS3 (Custom Cybersecurity SOC Design System with Dark/Light mode toggle and Glassmorphism), JavaScript (ES6+), Bootstrap 5.3, Bootstrap Icons, Chart.js.
- **Backend**: Python 3.11, Flask 3.0, Werkzeug, Jinja2.
- **Data Engineering**: Python, Pandas 2.2, PySpark (AWS Glue 4.0 job specification and blueprint).
- **Machine Learning**: Scikit-learn 1.5 (`IsolationForest`), NumPy, SciPy, Joblib.
- **Generative AI & RAG**: FAISS (`faiss-cpu`), TF-IDF dense L2-normalized vector embeddings, Google GenAI SDK (`google-genai`), OpenAI-ready interface, curated local security knowledge base.
- **Database & Storage**: Thread-safe SQLite with parameterized queries, WAL mode support, and foreign keys.
- **Testing**: Pytest with automated unit and integration tests across ingestion, ML detection, RAG retrieval, incident lifecycle, and API endpoints.

---

## 3. Project Folder Structure

```
CloudSentinel_AI/
├── app.py                      # Application entrypoint & bootstrap seeding
├── requirements.txt            # Python dependencies
├── pytest.ini                  # Pytest configuration
├── README.md                   # Complete system documentation
├── .env.example                # Sample environment configuration
├── .gitignore                  # Git exclusion rules
├── config/
│   └── config.py               # Centralized configuration & environment loader
├── database/
│   ├── db.py                   # Thread-safe SQLite connection & query helpers
│   └── schema.sql              # Database schema (tables, constraints, indexes)
├── models/
│   ├── anomaly_detector.py     # Isolation Forest ML model & explainability engine
│   └── model_store.py          # Model singleton and lifecycle manager
├── pipelines/
│   ├── log_parser.py           # CloudTrail JSON & CSV validator and parser
│   ├── pandas_pipeline.py      # Data Engineering ETL pipeline (dedup, normalize, features)
│   └── pyspark_pipeline.py     # AWS Glue / PySpark distributed ETL pipeline blueprint
├── services/
│   ├── ingestion_service.py    # Ingestion coordinator (parsing -> ETL -> threats)
│   ├── incident_service.py     # Threat correlation, incident lifecycle, containment actions
│   ├── rag_service.py          # RAG assistant with FAISS vector store & fallback mode
│   └── audit_service.py        # Immutable security operations audit logger
├── routes/
│   ├── api_routes.py           # REST API endpoints
│   └── web_routes.py           # Route controllers for all 10 views
├── data/
│   ├── sample_logs/            # Synthetic demonstration logs (JSON & CSV)
│   │   ├── cloudtrail_synthetic_mixed.json
│   │   └── cloudtrail_sample.csv
│   └── knowledge_base/         # Curated AWS security & MITRE ATT&CK playbooks
│       ├── aws_iam_privilege_escalation.md
│       ├── cloudtrail_evasion_tampering.md
│       ├── brute_force_credential_stuffing.md
│       ├── exfiltration_s3_data_access.md
│       ├── security_group_misconfiguration.md
│       └── incident_containment_runbooks.md
├── templates/                  # 10 UI views + base layout
│   ├── base.html               # Common SOC layout with dark/light mode toggle
│   ├── index.html              # View 1: Home & System Overview
│   ├── dashboard.html          # View 2: Security Monitoring Dashboard
│   ├── ingestion.html          # View 3: Log Upload & Ingestion
│   ├── events.html             # View 4: Normalized Event Explorer
│   ├── threats.html            # View 5: Threat & Anomaly List
│   ├── incident_detail.html    # View 6: Incident Dossier & Investigation
│   ├── assistant.html          # View 7: GenAI Security Assistant (RAG)
│   ├── incident_mgmt.html      # View 8: Incident Triage Queue
│   ├── knowledge_base.html     # View 9: Knowledge-Base Management
│   └── system_config.html      # View 10: System Config & Model Status
├── static/
│   ├── css/
│   │   └── style.css           # Custom Cybersecurity SOC styling
│   └── js/
│       ├── main.js             # Theme controller, toasts, simulated actions
│       └── dashboard.js        # Chart.js dynamic visualizers
├── tests/                      # Automated test suite (24 tests)
│   ├── test_ingestion.py
│   ├── test_ml_detection.py
│   ├── test_rag_service.py
│   ├── test_incident_mgmt.py
│   └── test_api.py
└── docs/                       # Architectural specifications
    ├── architecture.md
    ├── aws_deployment_guide.md
    └── data_pipeline_spec.md
```

---

## 4. Execution Instructions (Windows PowerShell)

Follow these exact Windows PowerShell commands to set up, test, and run the project:

### Step 1: Create and Activate Virtual Environment
```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

### Step 2: Install Dependencies
```powershell
pip install -r requirements.txt
```

### Step 3: Configure Environment Variables
```powershell
Copy-Item .env.example .env
```
*(No external API keys are required to run the local prototype. If you have a Google Gemini API key, you can optionally set `GEMINI_API_KEY` in `.env`)*

### Step 4: Run Automated Tests
Execute the full test suite (verifies ingestion, ML detection, FAISS vector search, and API endpoints):
```powershell
python -m pytest -v
```

### Step 5: Start the Application
```powershell
python app.py
```
Open your web browser and navigate to:
**`http://127.0.0.1:5000`**

---

## 5. System Verification & Transparency Matrix

| Capability | Local Prototype Status | Cloud Dependency / Extension |
| :--- | :--- | :--- |
| **CloudTrail Ingestion** | **100% Operational Locally** | Reads synthetic CloudTrail JSON and CSV files. Real S3 bucket streaming is configurable. |
| **Data Engineering ETL** | **100% Operational Locally** | Pandas pipeline performs schema normalization, RFC 1918 checking, and deduplication. PySpark Glue script available for EMR/Glue. |
| **ML Anomaly Detection** | **100% Operational Locally** | Scikit-learn Isolation Forest trained on 10 extracted security dimensions with explainable feature attribution. |
| **GenAI RAG Assistant** | **100% Operational Locally** | Local FAISS vector index with 29 chunks over 6 playbooks. Operates in transparent Fallback Demonstration Mode without requiring API keys. Live Google Gemini API active when key is supplied. |
| **Incident Management** | **100% Operational Locally** | Status updates (Open, Investigating, Resolved, False Positive), analyst notes, and audit logging fully persistent in SQLite. |
| **Containment Actions** | **Verified Simulated Mode** | Executes safety-governed simulations (Session Revocation, DenyAll inline policy, VPC NACL) without destructive cloud operations. |

---

## 6. Ten Dedicated Application Views

1. **Home & System Overview (`/`)**: High-level platform introduction, 4-domain integration cards, and local vs cloud architecture matrix.
2. **Security Dashboard (`/dashboard`)**: SOC monitoring dashboard with dynamic KPI cards, Chart.js severity doughnut, threat volume trends, and recent alerts.
3. **Log Ingestion & Upload (`/ingestion`)**: Drag-and-drop file uploader for CloudTrail JSON/CSV, interactive API tester, and ETL run history table.
4. **Normalized Event Explorer (`/events`)**: Searchable and filterable table of cleaned cloud events with RFC 1918 IP indicators.
5. **Threat & Anomaly List (`/threats`)**: Displays flagged threats with ML anomaly scores alongside rule triggers and feature attribution previews.
6. **Incident Details Dossier (`/incident/<id>`)**: In-depth incident telemetry, ML anomaly score gauge, feature contribution percentages, raw JSON viewer, and response buttons.
7. **GenAI Security Assistant (`/assistant`)**: Interactive RAG workbench retrieving relevant security playbooks from FAISS, generating threat explanations, investigation checklists, and remediation recommendations.
8. **Incident Management Queue (`/incident-mgmt`)**: Analyst triage queue with live status changer and containment simulation triggers.
9. **Knowledge-Base Management (`/knowledge-base`)**: Library of 6 curated cloud security playbooks with search and a "Rebuild FAISS Vector Index" trigger.
10. **System Config & Model Status (`/system-config`)**: Isolation Forest hyperparameters, retrain trigger, AWS integration status matrix, and immutable audit trail.
