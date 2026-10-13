# Suspicious Authentication & Credential Stuffing Investigation Guide

## 1. Threat Overview & MITRE ATT&CK Mapping
- **Technique ID**: T1110 (Brute Force), T1110.003 (Password Spraying), T1110.004 (Credential Stuffing)
- **Category**: Initial Access & Credential Access
- **Cloud Environment**: AWS IAM Console & Identity Center (SSO)

Adversaries attempt repeated programmatic or console authentications against AWS accounts to identify valid passwords or credentials leaked from third-party breaches. Credential stuffing involves testing lists of compromised username/password pairs, while password spraying attempts common passwords against many user accounts to bypass lockout policies.

## 2. Key Suspicious Indicators and Event Signatures
1. **Consecutive `ConsoleLogin` Failures**:
   - Multiple `errorMessage: Failed authentication` records originating from the same IP address or across multiple user identities within a brief window (e.g. 5 failures within 3 minutes).
2. **Geographic and Network Anomalies**:
   - Authentication attempts from unusual autonomous system numbers (ASNs), known Tor exit nodes, residential proxies, or foreign countries.
3. **Root Account Targeting**:
   - `ConsoleLogin` failure for `userIdentity.type == "Root"`. Root login attempts without MFA are considered High/Critical priority events.
4. **Sudden Login Following Multiple Failures**:
   - A sequence of 4+ failed `ConsoleLogin` events followed immediately by a successful `ConsoleLogin` from the same external IP indicates probable credential breach.

## 3. Investigation Protocol
1. Filter CloudTrail logs by `eventName: ConsoleLogin` and `errorCode: Exception` / `errorMessage: Failed authentication`.
2. Group attempts by `sourceIPAddress` and targeted `userName`.
3. Check if Multi-Factor Authentication (`additionalEventData.MFAUsed: "No"`) was bypassed or challenged.
4. If a successful login followed, inspect all actions performed by that session within the next 2 hours.

## 4. Response & Containment Playbook
1. **Lock Compromised IAM User**:
   - Reset console password and delete the user's login profile:
     `aws iam delete-login-profile --user-name <TargetUser>`
2. **Enforce MFA**:
   - Ensure IAM policies mandate MFA for all console sessions (`aws:MultiFactorAuthPresent: true`).
3. **Block Adversary IP via AWS WAF or Network ACL**:
   - Add the offending IP address to a rate-limiting or blocking IP set in AWS WAF or VPC NACL.
4. **Require Credential Re-authentication**:
   - Revoke active temporary STS credentials for the user.
