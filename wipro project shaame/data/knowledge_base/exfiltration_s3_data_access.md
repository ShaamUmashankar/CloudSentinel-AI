# Amazon S3 Data Exfiltration & Storage Exposure Remediation Guide

## 1. Threat Overview & MITRE ATT&CK Mapping
- **Technique ID**: T1530 (Data from Cloud Storage), T1567 (Exfiltration Over Web Service)
- **Category**: Exfiltration & Impact
- **Cloud Environment**: Amazon Simple Storage Service (Amazon S3), AWS KMS

Amazon S3 buckets store an enterprise's most sensitive data assets, including customer records, financial reports, backups, and proprietary source code. Attackers manipulate bucket access control lists (ACLs) or bucket policies to expose data publicly, or use compromised IAM credentials to mass-download objects.

## 2. Key Suspicious Indicators and High-Risk Events
1. **`PutBucketPolicy` / `PutBucketAcl`**:
   - Setting `Principal: "*"` or `AllUsers` (`http://acs.amazonaws.com/groups/global/AllUsers`) permissions, opening the bucket to public anonymous read/write.
2. **`DeleteBucketPolicy`**:
   - Removing security restrictions or IP-whitelisting policies on confidential data buckets.
3. **Mass `GetObject` Volumetric Anomalies**:
   - An unusual surge in `GetObject` requests or data transfer egress volume from an identity or external IP that historically has minimal S3 activity.
4. **`PutAccountPublicAccessBlock` Disabled**:
   - Turning off account-level S3 Block Public Access settings.
5. **AWS KMS Key Policy Tampering (`PutKeyPolicy`)**:
   - Granting external AWS accounts permission to decrypt customer master keys (CMKs) used for S3 encryption.

## 3. Investigation Protocol
1. Examine CloudTrail event `requestParameters` for the bucket name, ARN, and policy statement applied.
2. Check S3 server access logs or CloudTrail data events to calculate the total byte volume transferred.
3. Determine whether the data within the bucket is classified as PII, HIPAA, or PCI-DSS sensitive data.
4. Check if S3 object versioning and MFA delete were enabled.

## 4. Remediation & Hardening Steps
1. **Enable S3 Block Public Access**:
   - Apply account-wide or bucket-specific Block Public Access immediately:
     `aws s3api put-public-access-block --bucket <BucketName> --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true`
2. **Restore Secure Bucket Policy**:
   - Replace the permissive policy with a least-privilege policy restricted to specific VPC endpoints (`aws:sourceVpce`) and role ARNs.
3. **Rotate KMS Encryption Keys**:
   - If KMS permissions were modified, generate a new KMS Key and re-encrypt sensitive objects.
4. **Isolate or Revoke Perpetrator Identity**:
   - Quarantine the identity performing unauthorized S3 modifications.
