import pytest
import json
from app import create_app

@pytest.fixture
def client():
    app = create_app()
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client

def test_home_page(client):
    res = client.get("/")
    assert res.status_code == 200
    assert b"CloudSentinel" in res.data

def test_dashboard_page(client):
    res = client.get("/dashboard")
    assert res.status_code == 200
    assert b"Security Monitoring Dashboard" in res.data

def test_dashboard_stats_api(client):
    res = client.get("/api/dashboard/stats")
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert "total_events" in data
    assert "severity_counts" in data
    assert "trends" in data

def test_api_log_ingestion(client):
    event = {
        "eventID": "api-test-999",
        "eventTime": "2026-10-12T15:00:00Z",
        "eventName": "DescribeInstances",
        "eventSource": "ec2.amazonaws.com",
        "awsRegion": "us-east-1",
        "sourceIPAddress": "10.0.1.55",
        "userIdentity": {"type": "IAMUser", "userName": "test_bot"}
    }
    res = client.post("/api/logs/ingest", json=event)
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True

def test_api_events_list(client):
    res = client.get("/api/events")
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert "events" in data

def test_api_incidents_list(client):
    res = client.get("/api/incidents")
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert "incidents" in data

def test_api_rag_assistant_analyze(client):
    inc_res = client.get("/api/incidents?limit=1")
    inc_data = inc_res.get_json()
    if inc_data["incidents"]:
        inc_id = inc_data["incidents"][0]["id"]
        res = client.post("/api/assistant/analyze", json={
            "incident_id": inc_id,
            "query": "What are the recommended investigation steps?"
        })
        assert res.status_code == 200
        analysis = res.get_json()["analysis"]
        assert "explanation" in analysis
        assert "investigation_steps" in analysis
        assert len(analysis["investigation_steps"]) > 0

def test_api_model_status(client):
    res = client.get("/api/model/status")
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert data["status"]["is_ready"] is True
