from models.anomaly_detector import SecurityAnomalyDetector

_detector_instance = None

def get_anomaly_detector(force_reload: bool = False) -> SecurityAnomalyDetector:
    """Returns the singleton instance of SecurityAnomalyDetector."""
    global _detector_instance
    if _detector_instance is None or force_reload:
        _detector_instance = SecurityAnomalyDetector()
    return _detector_instance
