# AWS IAM Security & Privilege Escalation Mitigation Guide

## 1. Threat Overview & MITRE ATT&CK Mapping
- **Technique ID**: T1078 (Valid Accounts), T1098 (Account Manipulation), T1484 (Domain Policy Modification)
- **Category**: Privilege Escalation & Persistence
- **Cloud Environment**: Amazon Web Services (AWS) Identity and Access Management (IAM)

Privilege escalation occurs when an adversary gains unauthorized access to higher privileges than originally granted. In AWS environments, attackers frequently target IAM credentials (access keys, console passwords, or assumed role tokens) to grant themselves administrator privileges, create backdoor credentials, or circumvent organizational SCPs (Service Control Policies).

## 2. Key Suspicious Indicators and API Signatures
1. **`AttachUserPolicy` / `AttachRolePolicy`**:
   - Attackers attaching `arn:aws:iam::aws:policy/AdministratorAccess` or custom wildcard (`"Action": "*"`, `"Resource": "*"`) policies to unprivileged IAM users or roles.
   - Performed by an identity that does not belong to the Cloud Platform or DevOps Admin groups.
2. **`PutUserPolicy` / `PutRolePolicy`**:
   - Injection of inline policies containing wildcard permissions directly onto an entity.
3. **`CreateAccessKey`**:
   - Generating new programmatic access keys for a different existing user (e.g., target victim admin user), creating secondary persistence.
4. **`CreateLoginProfile` / `UpdateLoginProfile`**:
   - Activating AWS Management Console password access for accounts that previously only had API/CLI access.
5. **`AssumeRole` with Elevated Session**:
   - Assuming privileged roles across accounts or within the same account from unusual external IP addresses or anomalous user agents (e.g., Python `botocore`, Kali Linux tools).

## 3. Investigation Workflow
1. Verify the identity of the principal invoking the IAM action (`userIdentity.arn` in CloudTrail).
2. Check the source IP address (`sourceIPAddress`) against known corporate CIDRs, VPN gateways, and threat intelligence feeds.
3. Review CloudWatch metrics for subsequent API calls made by the modified principal.
4. Inspect whether MFA (`userIdentity.sessionContext.attributes.mfaAuthenticated`) was active during the request.
5. Check if the affected user identity had any recent anomalous failed login attempts (`ConsoleLogin` failure).

## 4. Recommended Containment & Remediation Actions
1. **Quarantine the Principal**:
   - Attach an explicit Deny policy immediately to halt all active actions:
   ```json
   {
     "Version": "2012-10-17",
     "Statement": [
       {
         "Effect": "Deny",
         "Action": "*",
         "Resource": "*"
       }
     ]
   }
   ```
2. **Revoke Active IAM Sessions**:
   - Apply an inline policy invalidating sessions issued before the incident timestamp (`aws:CurrentTime` vs `aws:TokenIssueTime`).
3. **Deactivate and Rotate Credentials**:
   - Deactivate all active access keys: `aws iam update-access-key --access-key-id <KEY_ID> --status Inactive --user-name <USER>`.
   - Force console password reset and invalidate active sessions.
4. **Audit and Rollback Permissions**:
   - Detach unauthorized policies: `aws iam detach-user-policy --user-name <USER> --policy-arn <POLICY_ARN>`.
   - Remove unauthorized inline policies.
