import pytest
import numpy as np
from models.anomaly_detector import SecurityAnomalyDetector, FEATURE_NAMES

def test_feature_extraction():
    detector = SecurityAnomalyDetector()
    normal_event = {
        "event_name": "DescribeInstances",
        "event_source": "ec2.amazonaws.com",
        "timestamp": "2026-10-12T11:00:00Z",
        "is_internal_ip": 1,
        "is_error": 0,
        "is_privilege_related": 0,
        "is_auth_failure": 0,
        "is_tampering": 0,
        "action_type": "Read",
        "user_type": "IAMUser",
        "risk_score": 0.1
    }
    features = detector.extract_features_single(normal_event)
    assert len(features) == len(FEATURE_NAMES)
    assert features[0] == 1.0 # is_internal_ip
    assert features[2] == 0.0 # is_privilege_related
    assert features[4] == 0.0 # is_tampering

def test_suspicious_event_features():
    detector = SecurityAnomalyDetector()
    attack_event = {
        "event_name": "StopLogging",
        "event_source": "cloudtrail.amazonaws.com",
        "timestamp": "2026-10-12T02:00:00Z", # off hours
        "is_internal_ip": 0, # external
        "is_error": 0,
        "is_privilege_related": 0,
        "is_auth_failure": 0,
        "is_tampering": 1,
        "action_type": "Write",
        "user_type": "Root",
        "risk_score": 0.9
    }
    features = detector.extract_features_single(attack_event)
    assert features[0] == 0.0 # is_internal_ip (external)
    assert features[4] == 1.0 # is_tampering
    assert features[5] == 1.0 # is_write_action
    assert features[7] == 1.0 # is_off_hours
    assert features[8] == 1.0 # user_type_risk Root

def test_model_training_and_scoring():
    detector = SecurityAnomalyDetector(contamination=0.1, threshold=0.6)
    seed_events = [
        {"event_name": "DescribeInstances", "event_source": "ec2.amazonaws.com", "timestamp": "2026-10-12T10:00:00Z", "is_internal_ip": 1, "is_error": 0, "is_privilege_related": 0, "is_auth_failure": 0, "is_tampering": 0, "action_type": "Read", "user_type": "IAMUser"},
        {"event_name": "GetCallerIdentity", "event_source": "sts.amazonaws.com", "timestamp": "2026-10-12T10:05:00Z", "is_internal_ip": 1, "is_error": 0, "is_privilege_related": 0, "is_auth_failure": 0, "is_tampering": 0, "action_type": "Read", "user_type": "IAMUser"},
        {"event_name": "ListBuckets", "event_source": "s3.amazonaws.com", "timestamp": "2026-10-12T10:10:00Z", "is_internal_ip": 1, "is_error": 0, "is_privilege_related": 0, "is_auth_failure": 0, "is_tampering": 0, "action_type": "Read", "user_type": "IAMUser"}
    ]
    meta = detector.train(seed_events)
    assert detector.model is not None
    assert meta["feature_count"] == 10

    # Predict normal event
    normal_pred = detector.predict_event(seed_events[0])
    assert 0.0 <= normal_pred["anomaly_score"] <= 1.0

    # Predict attack event
    attack_event = {
        "event_name": "StopLogging",
        "event_source": "cloudtrail.amazonaws.com",
        "timestamp": "2026-10-12T03:00:00Z",
        "is_internal_ip": 0,
        "is_error": 0,
        "is_privilege_related": 0,
        "is_auth_failure": 0,
        "is_tampering": 1,
        "action_type": "Write",
        "user_type": "Root"
    }
    attack_pred = detector.predict_event(attack_event)
    assert attack_pred["anomaly_score"] > normal_pred["anomaly_score"]
    assert len(attack_pred["contributions"]) > 0
    # Confirm explainability returned
    assert "description" in attack_pred["contributions"][0]
