import pytest
import json
from pipelines.log_parser import CloudTrailLogParser, LogParseError
from pipelines.pandas_pipeline import PandasETLPipeline

def test_validate_timestamp():
    assert CloudTrailLogParser.validate_timestamp("2026-10-12T14:30:00Z") is True
    assert CloudTrailLogParser.validate_timestamp("2026-10-12T14:30:00.123Z") is True
    assert CloudTrailLogParser.validate_timestamp("not-a-timestamp") is False
    assert CloudTrailLogParser.validate_timestamp("") is False

def test_parse_valid_json_log():
    raw_json = json.dumps({
        "Records": [
            {
                "eventID": "test-uuid-001",
                "eventTime": "2026-10-12T10:00:00Z",
                "eventName": "DescribeInstances",
                "eventSource": "ec2.amazonaws.com",
                "sourceIPAddress": "10.0.1.25",
                "userIdentity": {"type": "IAMUser", "userName": "test_user"}
            }
        ]
    })
    valid, rejected = CloudTrailLogParser.parse_content(raw_json, "test.json")
    assert len(valid) == 1
    assert len(rejected) == 0
    assert valid[0]["event_name"] == "DescribeInstances"
    assert valid[0]["user_name"] == "test_user"

def test_parse_invalid_malformed_records():
    raw_json = json.dumps({
        "Records": [
            {
                "eventID": "bad-001",
                "eventTime": "invalid-time",
                "eventName": "DescribeInstances",
                "eventSource": "ec2.amazonaws.com"
            },
            {
                "eventID": "bad-002",
                "eventTime": "2026-10-12T10:00:00Z"
                # Missing eventName and eventSource
            }
        ]
    })
    valid, rejected = CloudTrailLogParser.parse_content(raw_json, "bad.json")
    assert len(valid) == 0
    assert len(rejected) == 2
    assert "timestamp" in rejected[0]["reason"].lower()
    assert "eventname" in rejected[1]["reason"].lower()

def test_parse_csv_log():
    csv_content = """eventID,eventTime,eventName,eventSource,sourceIPAddress,userName
csv-test-1,2026-10-12T12:00:00Z,ListBuckets,s3.amazonaws.com,192.168.1.10,alice
csv-test-2,2026-10-12T12:05:00Z,GetSecretValue,secretsmanager.amazonaws.com,203.0.113.5,bob
"""
    valid, rejected = CloudTrailLogParser.parse_content(csv_content, "test.csv")
    assert len(valid) == 2
    assert len(rejected) == 0
    assert valid[0]["event_name"] == "ListBuckets"
    assert valid[1]["source_ip"] == "203.0.113.5"

def test_empty_content_raises_error():
    with pytest.raises(LogParseError):
        CloudTrailLogParser.parse_content("", "empty.json")

def test_private_ip_detection():
    assert PandasETLPipeline.is_private_ip("10.0.1.5") is True
    assert PandasETLPipeline.is_private_ip("192.168.10.1") is True
    assert PandasETLPipeline.is_private_ip("172.16.5.9") is True
    assert PandasETLPipeline.is_private_ip("127.0.0.1") is True
    assert PandasETLPipeline.is_private_ip("198.51.100.22") is False
    assert PandasETLPipeline.is_private_ip("185.220.101.5") is False
