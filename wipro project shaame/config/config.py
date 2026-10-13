import os
from pathlib import Path
from dotenv import load_dotenv

# Base Directory of the project
BASE_DIR = Path(__file__).resolve().parent.parent

# Load .env if present
load_dotenv(BASE_DIR / ".env")

class Config:
    BASE_DIR = BASE_DIR
    PROJECT_NAME = "CloudSentinel AI"
    VERSION = "1.0.0"
    SECRET_KEY = os.getenv("SECRET_KEY", "cloudsentinel-ai-super-secret-key-2026")
    
    # Database
    DATABASE_PATH = os.getenv("DATABASE_PATH", str(BASE_DIR / "data" / "cloudsentinel.db"))
    
    # Machine Learning
    ML_CONTAMINATION_RATE = float(os.getenv("ML_CONTAMINATION_RATE", "0.08"))
    ML_ANOMALY_THRESHOLD = float(os.getenv("ML_ANOMALY_THRESHOLD", "0.65"))
    ML_MODEL_PATH = os.getenv("ML_MODEL_PATH", str(BASE_DIR / "models" / "isolation_forest.joblib"))
    
    # Generative AI / RAG
    LLM_PROVIDER = os.getenv("LLM_PROVIDER", "fallback").lower()
    GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
    OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
    KNOWLEDGE_BASE_DIR = os.getenv("KNOWLEDGE_BASE_DIR", str(BASE_DIR / "data" / "knowledge_base"))
    FAISS_INDEX_PATH = os.getenv("FAISS_INDEX_PATH", str(BASE_DIR / "data" / "faiss_index.bin"))
    
    # AWS Cloud Extensions (Optional / Future Architecture)
    AWS_ENABLED = os.getenv("AWS_ENABLED", "False").lower() in ("true", "1", "t")
    AWS_REGION = os.getenv("AWS_REGION", "us-east-1")
    AWS_CLOUDTRAIL_BUCKET = os.getenv("AWS_CLOUDTRAIL_BUCKET", "demo-cloudtrail-logs-bucket")
    AWS_DYNAMODB_TABLE = os.getenv("AWS_DYNAMODB_TABLE", "CloudSentinel-Incidents")
    AWS_KMS_KEY_ID = os.getenv("AWS_KMS_KEY_ID", "alias/cloudsentinel-key")
    AWS_LAMBDA_ARN = os.getenv("AWS_LAMBDA_ARN", "")
    AWS_REDSHIFT_CLUSTER = os.getenv("AWS_REDSHIFT_CLUSTER", "")
    
    # Severity thresholds for composite scoring
    SEVERITY_THRESHOLDS = {
        "CRITICAL": 0.85,
        "HIGH": 0.70,
        "MEDIUM": 0.50,
        "LOW": 0.30
    }
