# CloudSentinel AI - Data Engineering & Pipeline Specification

## 1. Overview
The Data Engineering pipeline ingests, validates, standardizes, deduplicates, and derives security features from raw cloud audit logs.

## 2. Ingestion Format Support
| Format | Validation Rules | Fallbacks & Handling |
| :--- | :--- | :--- |
| **CloudTrail JSON** | Root object with `Records` array or single record object | Validates ISO-8601 UTC timestamp and non-empty `eventName` / `eventSource` |
| **CloudTrail CSV** | Headers `eventName` and `eventSource` mandatory | Maps CSV columns to standardized schema with synthesized `eventID` |

## 3. Schema Normalization Mapping
| Raw CloudTrail Field | Normalized Database Field | Transformation Rule |
| :--- | :--- | :--- |
| `eventTime` | `timestamp` | Parsed with `pd.to_datetime`, formatted to UTC `%Y-%m-%dT%H:%M:%SZ` |
| `sourceIPAddress` | `source_ip`, `is_internal_ip` | Checked against RFC 1918 subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.1`) |
| `userIdentity` | `principal_id`, `principal_type` | Extracted `userName`, `principalId`, and identity type (Root, IAMUser, AssumedRole) |
| `errorCode` | `is_error`, `error_code` | Binary flag `1` if error code exists, otherwise `0` |
| `requestParameters` | `target_resource` | Regex extraction of bucket name, user name, trail ARN, security group ID |
| `eventName` | `action_type` | Categorized as `Write` for state-mutating verbs, `Read` for describe/list |

## 4. Derived Security Feature Vectors (ML Input)
The pipeline computes a 10-dimensional numerical vector for every normalized event:
1. `is_internal_ip` (0.0 or 1.0)
2. `is_error` (0.0 or 1.0)
3. `is_privilege_related` (0.0 or 1.0)
4. `is_auth_failure` (0.0 or 1.0)
5. `is_tampering` (0.0 or 1.0)
6. `is_write_action` (0.0 or 1.0)
7. `hour_of_day_norm` (0.0 to 1.0)
8. `is_off_hours` (0.0 or 1.0)
9. `user_type_risk` (0.2 for IAMUser, 0.5 for AssumedRole, 1.0 for Root)
10. `event_rarity_score` (0.0 to 1.0 based on historical dataset frequency)

## 5. Deduplication Algorithm
1. **In-Flight Batch Deduplication**: Drops duplicate records within the uploaded payload matching on `eventID`.
2. **Persistent Database Deduplication**: Queries existing `event_id` keys from `raw_logs` and rejects previously ingested events.
3. **Accounting Record**: Logs exact duplicate counts to `etl_runs` table.
