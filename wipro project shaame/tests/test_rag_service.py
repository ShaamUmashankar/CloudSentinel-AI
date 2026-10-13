import pytest
from services.rag_service import RAGSecurityAssistant

def test_rag_assistant_initialization():
    rag = RAGSecurityAssistant()
    status = rag.get_status()
    assert status["faiss_index_ready"] is True
    assert status["total_indexed_chunks"] > 0
    assert status["knowledge_docs_count"] >= 5

def test_rag_retrieval_relevance():
    rag = RAGSecurityAssistant()
    # Test IAM Privilege Escalation query
    results_iam = rag.retrieve_guidance("AttachUserPolicy AdministratorAccess Privilege Escalation", top_k=2)
    assert len(results_iam) > 0
    assert "IAM" in results_iam[0]["document_title"] or "Privilege" in results_iam[0]["document_title"]

    # Test Defense Evasion query
    results_evasion = rag.retrieve_guidance("StopLogging DeleteTrail disable CloudTrail audit logging", top_k=2)
    assert len(results_evasion) > 0
    assert "CloudTrail" in results_evasion[0]["document_title"] or "Evasion" in results_evasion[0]["document_title"]

def test_fallback_demonstration_mode():
    rag = RAGSecurityAssistant()
    mock_incident = {
        "incident_code": "INC-TEST-001",
        "title": "CRITICAL: CloudTrail Audit Logging Terminated",
        "event_name": "StopLogging",
        "principal": "compromised.user",
        "source_ip": "198.51.100.22",
        "severity": "CRITICAL",
        "ml_anomaly_score": 0.92,
        "rule_triggered": "RULE-EVASION-01",
        "risk_factors": "StopLogging; External IP",
        "event_time": "2026-10-12T02:00:00Z"
    }

    res = rag.analyze_incident(mock_incident)
    # Validate required keys per prompt specification
    assert "explanation" in res
    assert "observed_evidence" in res
    assert "investigation_steps" in res
    assert "remediation_recommendations" in res
    assert "sources_cited" in res
    assert "uncertainty_assessment" in res
    assert res["is_fallback"] is True
    assert "Fallback Demonstration Engine" in res["provider"]
    assert len(res["investigation_steps"]) >= 3
    assert len(res["remediation_recommendations"]) >= 3
    assert len(res["sources_cited"]) > 0
