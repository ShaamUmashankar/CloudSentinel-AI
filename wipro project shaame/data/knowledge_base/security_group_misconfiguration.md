# AWS Security Group Misconfiguration & Perimeter Exposure Guide

## 1. Threat Overview & MITRE ATT&CK Mapping
- **Technique ID**: T1190 (Exploit Public-Facing Application), T1562 (Impair Defenses)
- **Category**: Initial Access & Lateral Movement
- **Cloud Environment**: Amazon VPC, Amazon EC2 Security Groups

Security groups act as virtual stateful firewalls controlling inbound and outbound traffic for EC2 instances, RDS databases, and load balancers. Accidental or adversary-induced opening of administrative ports to `0.0.0.0/0` (the entire Internet) creates instant attack surface for brute force, vulnerability scanning, and remote code execution.

## 2. Key Suspicious Indicators and API Signatures
1. **`AuthorizeSecurityGroupIngress`**:
   - Rule adding CIDR `0.0.0.0/0` or `::/0` with `fromPort: 22` (SSH), `fromPort: 3389` (RDP), `fromPort: 3306` (MySQL), or `fromPort: 5432` (PostgreSQL).
2. **`ModifySecurityGroupRules`**:
   - Replacing internal VPN CIDRs with broad public ranges.
3. **`AuthorizeSecurityGroupEgress`**:
   - Allowing unrestricted outbound traffic on non-standard ports to enable reverse shell connections or command-and-control (C2) beaconing.
4. **`RunInstances` with High-Compute Shapes**:
   - Concurrently launching GPU-heavy instances (e.g. `g5.12xlarge`) or mining instances attached to newly opened security groups.

## 3. Investigation Protocol
1. Extract `requestParameters.groupId` or `requestParameters.ipPermissions` from CloudTrail.
2. Cross-reference the security group ID against active EC2 instances and ENIs (Elastic Network Interfaces).
3. Review whether VPC Flow Logs detect active ingress connection spikes or external port scans hitting the instance.
4. Check whether AWS Systems Manager (SSM) Session Manager is available as an alternative to exposing port 22/3389.

## 4. Remediation & Containment Actions
1. **Revoke Ingress Rule**:
   - Immediately delete the unrestricted rule:
     `aws ec2 revoke-security-group-ingress --group-id <GroupId> --protocol tcp --port 22 --cidr 0.0.0.0/0`
2. **Apply Default Restrictive Security Group**:
   - Reassign the network interface to a quarantine security group with no inbound ingress.
3. **Migrate to AWS SSM Session Manager**:
   - Eliminate direct public SSH/RDP ingress by utilizing IAM-governed AWS SSM.
4. **Deploy AWS Config Auto-Remediation**:
   - Activate AWS Config managed rule `restricted-ssh` with automated remediation Lambda.
