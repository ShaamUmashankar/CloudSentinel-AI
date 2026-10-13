import os
import joblib
import numpy as np
import pandas as pd
from pathlib import Path
from typing import List, Dict, Any, Tuple
from sklearn.ensemble import IsolationForest
from config.config import Config

FEATURE_NAMES = [
    "is_internal_ip",
    "is_error",
    "is_privilege_related",
    "is_auth_failure",
    "is_tampering",
    "is_write_action",
    "hour_of_day_norm",
    "is_off_hours",
    "user_type_risk",
    "event_rarity_score"
]

class SecurityAnomalyDetector:
    """
    Machine Learning Anomaly Detection for Cloud Security Events using scikit-learn Isolation Forest.
    Generates continuous anomaly scores, classifies suspicious events, and computes
    explainable feature attributions for SOC analysts.
    """

    def __init__(self, contamination: float = None, threshold: float = None, model_path: str = None):
        self.contamination = contamination if contamination is not None else Config.ML_CONTAMINATION_RATE
        self.threshold = threshold if threshold is not None else Config.ML_ANOMALY_THRESHOLD
        self.model_path = Path(model_path if model_path is not None else Config.ML_MODEL_PATH)
        self.model: IsolationForest = None
        self.feature_means: np.ndarray = None
        self.training_metadata: Dict[str, Any] = {}
        self._load_if_exists()

    def _load_if_exists(self):
        if self.model_path.exists():
            try:
                bundle = joblib.load(str(self.model_path))
                self.model = bundle.get("model")
                self.feature_means = bundle.get("feature_means")
                self.training_metadata = bundle.get("metadata", {})
                self.threshold = bundle.get("threshold", self.threshold)
                self.contamination = bundle.get("contamination", self.contamination)
            except Exception as e:
                print(f"[ML Warning] Failed to load model from {self.model_path}: {e}")
                self.model = None

    def save(self):
        self.model_path.parent.mkdir(parents=True, exist_ok=True)
        bundle = {
            "model": self.model,
            "feature_means": self.feature_means,
            "metadata": self.training_metadata,
            "threshold": self.threshold,
            "contamination": self.contamination
        }
        joblib.dump(bundle, str(self.model_path))

    @staticmethod
    def extract_features_single(event: Dict[str, Any], event_freq_map: Dict[str, float] = None) -> np.ndarray:
        """Extracts 10 numerical features from a single event dictionary."""
        is_internal = float(event.get("is_internal_ip", 0))
        is_error = float(event.get("is_error", 0))
        is_privilege = float(event.get("is_privilege_related", 0))
        is_auth_fail = float(event.get("is_auth_failure", 0))
        is_tampering = float(event.get("is_tampering", 0))
        
        action_type = event.get("action_type", "Read")
        is_write = 1.0 if action_type == "Write" else 0.0

        # Parse hour from timestamp
        ts_str = event.get("timestamp") or event.get("event_time", "")
        hour = 12
        if ts_str:
            try:
                dt = pd.to_datetime(ts_str, utc=True)
                hour = dt.hour
            except Exception:
                hour = 12

        hour_norm = hour / 24.0
        # Off-hours defined as before 07:00 UTC or after 20:00 UTC
        is_off_hours = 1.0 if (hour < 7 or hour > 20) else 0.0

        # User type risk encoding
        ut = str(event.get("principal_type") or event.get("user_type", "IAMUser")).lower()
        if "root" in ut:
            user_risk = 1.0
        elif "assumed" in ut or "role" in ut:
            user_risk = 0.5
        elif "federated" in ut:
            user_risk = 0.4
        else:
            user_risk = 0.2

        # Event rarity score (0.0 to 1.0)
        event_name = event.get("event_name", "")
        rarity = 0.5
        if event_freq_map:
            rarity = event_freq_map.get(event_name, 0.5)
        else:
            # Default rarity heuristic based on standard security events
            common_events = {"DescribeInstances", "GetCallerIdentity", "ListBuckets", "DescribeSecurityGroups", "DescribeKey", "DescribeAlarms"}
            rarity = 0.1 if event_name in common_events else 0.8

        return np.array([
            is_internal,
            is_error,
            is_privilege,
            is_auth_fail,
            is_tampering,
            is_write,
            hour_norm,
            is_off_hours,
            user_risk,
            rarity
        ], dtype=float)

    def extract_features_df(self, df: pd.DataFrame) -> Tuple[np.ndarray, Dict[str, float]]:
        """Extracts feature matrix from a Pandas DataFrame of events."""
        event_counts = df["event_name"].value_counts(normalize=True).to_dict()
        # Rarity is inverse of frequency
        rarity_map = {name: round(1.0 - freq, 4) for name, freq in event_counts.items()}

        features = []
        for _, row in df.iterrows():
            feat = self.extract_features_single(row.to_dict(), rarity_map)
            features.append(feat)

        return np.array(features, dtype=float), rarity_map

    def train(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Trains the Isolation Forest model on normalized security events."""
        if len(events) < 5:
            # Need at least a small set; generate synthetic baseline if sparse
            events = self._generate_synthetic_baseline(events)

        df = pd.DataFrame(events)
        X, rarity_map = self.extract_features_df(df)

        self.model = IsolationForest(
            n_estimators=100,
            contamination=self.contamination,
            random_state=42,
            n_jobs=-1
        )
        self.model.fit(X)

        self.feature_means = np.mean(X, axis=0)
        self.training_metadata = {
            "sample_count": len(events),
            "feature_count": X.shape[1],
            "trained_at": pd.Timestamp.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
            "contamination_rate": self.contamination,
            "anomaly_threshold": self.threshold,
            "feature_names": FEATURE_NAMES
        }
        self.save()
        return self.training_metadata

    def predict_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Calculates anomaly score, classification, and explainable feature contributions.
        Returns: {
            "anomaly_score": float, # 0.0 to 1.0 (higher = more anomalous)
            "is_anomaly": bool,
            "decision_score": float,
            "contributions": List[Dict[str, Any]],
            "model_ready": bool
        }
        """
        if self.model is None or self.feature_means is None:
            # Fallback heuristic if model not yet trained
            return self._heuristic_prediction(event)

        x = self.extract_features_single(event).reshape(1, -1)
        
        # Isolation Forest decision_function: negative is anomalous, positive is normal.
        raw_decision = float(self.model.decision_function(x)[0])
        
        # Calibrate to a continuous 0.0 - 1.0 anomaly score (higher = more anomalous)
        # Typically decision ranges between -0.3 to +0.3
        anomaly_score = float(1.0 / (1.0 + np.exp(raw_decision * 8.0)))
        anomaly_score = round(min(max(anomaly_score, 0.0), 1.0), 4)

        is_anomaly = anomaly_score >= self.threshold

        # Compute explainable feature contributions
        contributions = self._compute_feature_contributions(x[0], anomaly_score)

        return {
            "anomaly_score": anomaly_score,
            "is_anomaly": is_anomaly,
            "decision_score": round(raw_decision, 4),
            "contributions": contributions,
            "model_ready": True
        }

    def _compute_feature_contributions(self, feature_vec: np.ndarray, anomaly_score: float) -> List[Dict[str, Any]]:
        """
        Computes SHAP-like directional feature attribution.
        Compares the observed event's features against baseline normal feature means.
        """
        deltas = []
        feature_labels = {
            "is_internal_ip": ("Source IP Location", "Public / External IP Address"),
            "is_error": ("Execution Status", "API Authentication Error / Failure"),
            "is_privilege_related": ("Privilege Modification", "IAM Permission Escalation / Policy Attachment"),
            "is_auth_failure": ("Authentication Failures", "Repeated Console Login Auth Failures"),
            "is_tampering": ("Defense Evasion", "CloudTrail Logging Termination / Trail Tampering"),
            "is_write_action": ("Action Type", "Mutating / Destructive State Change"),
            "hour_of_day_norm": ("Time Window", "Anomalous Operating Time"),
            "is_off_hours": ("Operating Hours", "Off-hours Execution Outside Working Day"),
            "user_type_risk": ("Identity Privilege", "Elevated Identity / Root Role Session"),
            "event_rarity_score": ("Event Frequency", "Unusually Rare API Invocation Frequency")
        }

        for idx, name in enumerate(FEATURE_NAMES):
            diff = feature_vec[idx] - self.feature_means[idx]
            # Invert for internal_ip since 0 (external) is more anomalous than 1 (internal)
            if name == "is_internal_ip":
                weight = (1.0 - feature_vec[idx]) * 1.5
            else:
                weight = max(diff, 0.0)

            if weight > 0.05:
                label_pair = feature_labels.get(name, (name, name))
                deltas.append({
                    "feature": name,
                    "label": label_pair[0],
                    "reason": label_pair[1],
                    "weight": weight
                })

        # Normalize weights to percentage contribution
        total_weight = sum(d["weight"] for d in deltas) if deltas else 1.0
        contributions = []
        for d in sorted(deltas, key=lambda x: x["weight"], reverse=True)[:5]:
            pct = int(round((d["weight"] / total_weight) * 100))
            contributions.append({
                "feature": d["feature"],
                "label": d["label"],
                "percentage": pct,
                "description": f"{d['label']}: {d['reason']} (+{pct}%)"
            })

        return contributions

    def _heuristic_prediction(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Provides an interim heuristic prediction before model training."""
        base_risk = float(event.get("risk_score", 0.2))
        contributions = []
        if event.get("is_tampering"):
            contributions.append({"feature": "is_tampering", "label": "Defense Evasion", "percentage": 40, "description": "CloudTrail Audit Logging Disabled (+40%)"})
        if event.get("is_privilege_related"):
            contributions.append({"feature": "is_privilege_related", "label": "Privilege Escalation", "percentage": 30, "description": "IAM Administrator Policy Attached (+30%)"})
        if event.get("is_auth_failure"):
            contributions.append({"feature": "is_auth_failure", "label": "Auth Failure", "percentage": 20, "description": "Failed Console Authentication (+20%)"})
        if not event.get("is_internal_ip", 1):
            contributions.append({"feature": "is_internal_ip", "label": "External IP", "percentage": 10, "description": "Public / Non-VPC IP Address (+10%)"})

        return {
            "anomaly_score": base_risk,
            "is_anomaly": base_risk >= self.threshold,
            "decision_score": round(0.5 - base_risk, 4),
            "contributions": contributions,
            "model_ready": False
        }

    def _generate_synthetic_baseline(self, seed_events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Augments sparse events with synthetic normal cloud activity baseline for initial training."""
        synthetic = list(seed_events)
        normal_names = ["DescribeInstances", "GetCallerIdentity", "ListBuckets", "DescribeSecurityGroups", "DescribeKey"]
        for i in range(25):
            synthetic.append({
                "event_name": normal_names[i % len(normal_names)],
                "event_source": "ec2.amazonaws.com" if i % 2 == 0 else "s3.amazonaws.com",
                "timestamp": f"2026-10-12T{10 + (i % 6):02d}:00:00Z",
                "is_internal_ip": 1,
                "is_error": 0,
                "is_privilege_related": 0,
                "is_auth_failure": 0,
                "is_tampering": 0,
                "action_type": "Read",
                "user_type": "IAMUser",
                "risk_score": 0.1
            })
        return synthetic

    def get_status(self) -> Dict[str, Any]:
        """Returns model health, readiness, and parameters."""
        return {
            "is_ready": self.model is not None,
            "model_type": "Isolation Forest (scikit-learn)",
            "contamination_rate": self.contamination,
            "anomaly_threshold": self.threshold,
            "model_path": str(self.model_path),
            "features_used": FEATURE_NAMES,
            "training_metadata": self.training_metadata
        }
