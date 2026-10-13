import pytest
from services.incident_service import IncidentService
from services.audit_service import AuditService

def test_get_incidents():
    incidents = IncidentService.get_incidents(limit=10)
    assert isinstance(incidents, list)
    if len(incidents) > 0:
        inc = incidents[0]
        assert "incident_code" in inc
        assert "severity" in inc
        assert "status" in inc

def test_incident_status_update_and_notes():
    incidents = IncidentService.get_incidents(limit=1)
    if not incidents:
        pytest.skip("No incidents in database to test status update")

    inc_id = incidents[0]["id"]
    
    # Update to Investigating
    assert IncidentService.update_incident_status(inc_id, "Investigating") is True
    updated = IncidentService.get_incident_by_id(inc_id)
    assert updated["status"] == "Investigating"

    # Add Note
    note_id = IncidentService.add_analyst_note(inc_id, "Test SOC note for triage investigation", author="Senior_Analyst")
    assert note_id > 0
    refreshed = IncidentService.get_incident_by_id(inc_id)
    assert any(n["note"] == "Test SOC note for triage investigation" for n in refreshed["notes"])

def test_invalid_status_rejected():
    incidents = IncidentService.get_incidents(limit=1)
    if not incidents:
        pytest.skip("No incidents in database")

    with pytest.raises(ValueError):
        IncidentService.update_incident_status(incidents[0]["id"], "INVALID_STATUS")

def test_simulated_containment_action():
    incidents = IncidentService.get_incidents(limit=1)
    if not incidents:
        pytest.skip("No incidents in database")

    inc_id = incidents[0]["id"]
    res = IncidentService.execute_simulated_response(inc_id, "REVOKE_SESSION", actor="Lead_Analyst")
    assert res["status"] == "Simulated (Verified Safe)"
    assert "REVOKE_SESSION" in res["action_name"] or "Revoke" in res["action_name"]
    assert "recommended_aws_command" in res

    # Verify action logged in audit trail
    recent_audits = AuditService.get_recent_logs(limit=5)
    assert any(a["action_name"] == "REVOKE_SESSION" for a in recent_audits)
