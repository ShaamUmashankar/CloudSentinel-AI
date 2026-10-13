# Autonomous & Assisted Cloud Incident Containment Standard Operating Procedures

## 1. Principles of Cloud Incident Response
1. **Safety First**: Autonomous or semi-autonomous remediation actions must require human confirmation or pre-authorized policy guards to prevent unintended production outages.
2. **Auditability**: Every action, actor, timestamp, and target entity must be logged to an immutable audit trail.
3. **Preservation of Evidence**: Ensure snapshotting and CloudTrail retention prior to terminating resources.
4. **Least Disruptive Containment**: Prefer credential revocation and temporary quarantine over permanent deletion.

## 2. Standard Containment Actions Catalog

### Action A: Revoke Active IAM Session
- **Purpose**: Instantly terminates active AWS STS temporary credentials without deleting the user account.
- **Mechanism**: Attaches an inline policy that rejects any request whose token issue timestamp is older than current time:
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*",
      "Condition": {
        "DateLessThan": {
          "aws:TokenIssueTime": "2026-10-12T18:00:00Z"
        }
      }
    }
  ]
}
```

### Action B: Attach Temporary DenyAll Quarantine Policy
- **Purpose**: Halts all AWS API execution for a suspicious IAM entity while preserving the identity for forensic audit.
- **Target**: IAM User or Role ARN.
- **Rollback**: Detach policy when investigation completes or identity is verified.

### Action C: Rotate Access Key & Deactivate Active Key
- **Purpose**: Mitigates active credential exposure while providing a replacement secret.
- **CLI Equivalent**: `aws iam update-access-key --access-key-id <KEY_ID> --status Inactive`

### Action D: Isolate Source IP via Network ACL / WAF
- **Purpose**: Drops all inbound network packets from an active attacking IP or subnet across the VPC or API Gateway perimeter.
- **Target**: Attacking IP (e.g. 198.51.100.44).

### Action E: Restore CloudTrail Multi-Region Logging
- **Purpose**: Counteracts defense evasion tampering by automatically restarting stopped audit trails.

## 3. Human-in-the-Loop Verification
All remediation actions within CloudSentinel AI operate in **Assisted Response Mode** with Analyst confirmation modals to prevent accidental disruption of production workloads. Each action records simulation parameters and returns verified mock or live results.
