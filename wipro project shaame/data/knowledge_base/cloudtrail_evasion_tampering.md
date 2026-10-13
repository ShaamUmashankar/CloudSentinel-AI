# AWS CloudTrail Defense Evasion & Log Tampering Response Guide

## 1. Threat Overview & MITRE ATT&CK Mapping
- **Technique ID**: T1562.001 (Impair Defenses: Disable or Modify Tools)
- **Category**: Defense Evasion
- **Cloud Environment**: AWS CloudTrail, Amazon CloudWatch Logs, AWS Config

Adversaries disable or degrade cloud audit logging to conceal subsequent malicious operations such as data exfiltration, cryptomining deployment, or infrastructure modification. Tampering with CloudTrail trails is among the highest severity alerts in AWS environments, as it blinds security monitoring tools, SIEM pipelines, and SOC analysts.

## 2. Key Suspicious Indicators and High-Severity Events
1. **`StopLogging`**:
   - Explicitly halts the recording of AWS API activities for a specified CloudTrail trail.
2. **`DeleteTrail`**:
   - Completely removes a CloudTrail trail and stops all logging permanently.
3. **`UpdateTrail`**:
   - Disabling `IsMultiRegionTrail` or `IncludeGlobalServiceEvents` to blind specific regions or IAM global events.
   - Modifying S3 bucket delivery targets to redirect or drop logs.
4. **`PutEventSelectors`**:
   - Filtering out read/write management events or data events, preventing logging of critical AWS operations.
5. **`DeleteFlowLogs` / `DisableAlarm`**:
   - Disabling VPC flow logging or disabling CloudWatch security alarms.

## 3. Immediate Investigation Checklist
1. Identify the caller entity: Extract `userIdentity.principalId`, `userIdentity.arn`, and `sourceIPAddress`.
2. Determine if the action occurred from an authorized automated CI/CD pipeline (e.g., Terraform role) or an interactive user session.
3. Check for contemporaneous actions by the same caller in the 15 minutes before and after the tampering event.
4. Verify whether CloudTrail logs were configured with multi-region and S3 bucket Object Lock (WORM compliance).

## 4. Immediate Incident Response Runbook
1. **Restore Logging Immediately**:
   - Re-enable the trail without delay:
     `aws cloudtrail start-logging --name <TrailName>`
2. **Quarantine Compromised Credentials**:
   - Invalidate the active credentials used to perform the evasion action.
   - Attach the AWS managed policy `AWSCompromisedKeyQuarantine` or an inline Deny-All policy.
3. **Audit S3 Trail Bucket Integrity**:
   - Inspect the S3 bucket storing logs for any unauthorized `DeleteObject` or bucket lifecycle rule alterations.
4. **Enforce Organization SCPs**:
   - Enforce an AWS Organizations Service Control Policy that explicitly blocks `cloudtrail:StopLogging`, `cloudtrail:DeleteTrail`, and `cloudtrail:UpdateTrail` from being executed by member account administrators.
