# Encryption Implementation - BuildIT Infrastructure

This document describes the encryption implementation for the BuildIT infrastructure, following the authoritative encryption placement guidelines.

## Encryption Summary

**Rule**: Encrypt at the edge and at storage. Do not encrypt inside trusted execution paths.

---

## 1. Encryption in Transit (Trust Boundary)

### ✅ Client → Application Load Balancer (MANDATORY)

**Implementation**: HTTPS/TLS 1.2 & 1.3

**Configuration**:
```terraform
# File: main.tf
resource "aws_lb_listener" "https" {
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = var.acm_certificate_arn
}
```

**Requirements**:
- TLS termination at ALB
- AWS Certificate Manager (ACM) certificate required
- Minimum TLS 1.2, supports TLS 1.3
- Protects against: MITM attacks, credential theft, data leakage

**Setup**:
1. Create/import certificate in AWS Certificate Manager
2. Set `acm_certificate_arn` variable in `terraform.tfvars`
3. HTTPS listener will be automatically created

### ❌ ALB → Web EC2 (OPTIONAL - NOT IMPLEMENTED)

**Reason**: Traffic stays inside VPC, protected by private subnets + security groups

**Current Implementation**: Plain HTTP on port 80

### ❌ Web EC2 → NLB → Turbo EC2 (NOT REQUIRED)

**Reason**: 
- Entirely internal VPC traffic
- Strict security group enforcement
- No internet exposure
- Performance-sensitive execution path

**Current Implementation**: Plain TCP on port 8080

---

## 2. Encryption at Rest (Data Protection)

### ✅ EBS Volumes (MANDATORY)

**Applies to**:
- Web EC2 instances (root volumes)
- Turbo EC2 instances (root volumes)

**Implementation**:
```terraform
# File: main.tf - Both launch templates
block_device_mappings {
  device_name = "/dev/xvda"
  ebs {
    volume_size           = var.ebs_volume_size
    volume_type           = "gp3"
    delete_on_termination = true
    encrypted             = true  # ← ENCRYPTION ENABLED
  }
}
```

**Details**:
- Algorithm: AES-256 (AWS-managed)
- Key Management: AWS-managed KMS key
- Automatic for all instances launched from templates
- Protects against: snapshot theft, disk reuse, insider access

### ✅ RDS PostgreSQL (MANDATORY)

**Implementation**:
```terraform
# File: main.tf
resource "aws_db_instance" "main" {
  engine            = "postgres"
  storage_encrypted = true  # ← ENCRYPTION ENABLED
  # AWS-managed KMS key used by default
}
```

**Details**:
- Algorithm: AES-256 (transparent to application)
- Key Management: AWS-managed KMS key
- Automatic backup encryption
- Protects: user data, execution metadata, logs

### ⚠️ ElastiCache Valkey (STRONGLY RECOMMENDED)

**Implementation**:
```terraform
# File: main.tf
resource "aws_elasticache_replication_group" "main" {
  at_rest_encryption_enabled = true  # ← ENCRYPTION ENABLED
  kms_key_id                 = null  # AWS-managed key
}
```

**Details**:
- Algorithm: AES-256
- Key Management: AWS-managed KMS key
- Defense in depth strategy
- Minimal performance impact
- No in-transit encryption (not required for internal cache)

### ✅ AMIs & Snapshots (AUTOMATIC)

**Implementation**: Inherited automatically

**Details**:
- AMIs inherit encryption from source EBS snapshots
- RDS automated backups encrypted when source is encrypted
- No additional configuration required

---

## 3. What Is NOT Encrypted (By Design)

### ❌ Application Payloads
- No manual encryption of execution jobs
- No encrypted JSON payloads
- Reason: Unnecessary complexity, handled at storage layer

### ❌ Internal Service Communication
- Web EC2 ↔ Turbo EC2: Plain TCP
- Turbo EC2 ↔ ElastiCache: Plain Redis protocol
- Reason: Private VPC, security groups, performance-sensitive

### ❌ Custom Cryptography
- Never write encryption code
- Never manage keys manually
- Reason: AWS-managed encryption is sufficient

---

## 4. Encryption Matrix

| Layer                    | Encryption Type    | Status | Protects Against                        |
|--------------------------|-------------------|--------|-----------------------------------------|
| Client → ALB             | TLS 1.2/1.3       | ✅     | MITM, credential theft, data leakage    |
| ALB → Web EC2            | None              | ❌     | Not required (private VPC)              |
| Web EC2 → NLB → Turbo    | None              | ❌     | Not required (private VPC)              |
| EBS (Web EC2)            | AES-256 at rest   | ✅     | Snapshot theft, disk reuse              |
| EBS (Turbo EC2)          | AES-256 at rest   | ✅     | Snapshot theft, disk reuse              |
| RDS PostgreSQL           | AES-256 at rest   | ✅     | Data breach, unauthorized access        |
| ElastiCache (Valkey)     | AES-256 at rest   | ✅     | Defense in depth                        |
| AMIs                     | Inherited         | ✅     | Automatic from EBS                      |
| RDS Backups              | Inherited         | ✅     | Automatic from RDS                      |

---

## 5. Deployment Instructions

### Initial Setup

1. **Create ACM Certificate** (for HTTPS):
   ```bash
   # Request certificate in AWS Console or CLI
   aws acm request-certificate \
     --domain-name yourdomain.com \
     --validation-method DNS \
     --region ap-south-1
   ```

2. **Configure Terraform Variables**:
   ```hcl
   # File: terraform.tfvars
   acm_certificate_arn = "arn:aws:acm:ap-south-1:ACCOUNT:certificate/CERT_ID"
   ```

3. **Deploy Infrastructure**:
   ```bash
   terraform init
   terraform plan
   terraform apply
   ```

### Verification

**Check EBS Encryption**:
```bash
aws ec2 describe-volumes \
  --filters "Name=tag:Name,Values=buildit-*" \
  --query 'Volumes[*].[VolumeId,Encrypted]' \
  --output table
```

**Check RDS Encryption**:
```bash
aws rds describe-db-instances \
  --db-instance-identifier buildit-postgres \
  --query 'DBInstances[0].StorageEncrypted'
```

**Check ElastiCache Encryption**:
```bash
aws elasticache describe-replication-groups \
  --replication-group-id buildit-cache \
  --query 'ReplicationGroups[0].AtRestEncryptionEnabled'
```

**Check ALB Listeners**:
```bash
aws elbv2 describe-listeners \
  --load-balancer-arn $(terraform output -raw alb_arn) \
  --query 'Listeners[*].[Port,Protocol,SslPolicy]' \
  --output table
```

---

## 6. Compliance & Security Notes

### Production Readiness
✅ All persistent storage encrypted at rest  
✅ Public ingress traffic encrypted in transit  
✅ AWS-managed keys (no key management overhead)  
✅ Automatic snapshot encryption  
✅ Defense in depth for cache layer  

### Performance Impact
- **TLS at ALB**: Negligible (TLS termination at edge)
- **EBS Encryption**: Negligible (hardware-accelerated)
- **RDS Encryption**: Negligible (transparent encryption)
- **ElastiCache Encryption**: < 5% overhead at rest only

### Cost Impact
- EBS encryption: No additional cost
- RDS encryption: No additional cost
- ElastiCache encryption: No additional cost
- ACM certificate: Free for public certificates

---

## 7. Architecture Decision Record

**Question**: Why no TLS between internal services?

**Answer**: Internal traffic within private subnets is protected by:
1. VPC isolation (no external routing)
2. Security group enforcement (explicit allow rules)
3. No internet gateway access from private subnets
4. Network ACLs (default deny)

Adding TLS internally would:
- Increase complexity (certificate management)
- Reduce performance (encryption overhead)
- Provide minimal security benefit (already defense-in-depth)

**Quote from Security Guidelines**:
> "Encrypt at the edge and at storage. Do not encrypt inside trusted execution paths."

---

## 8. One-Line Summary

**"We encrypt all public ingress traffic at the ALB and all persistent storage at rest using AWS-managed encryption, while internal execution traffic remains unencrypted inside private subnets for performance and simplicity."**

---

## 9. Future Considerations

### Optional Enhancements (Not Currently Required)
- Custom KMS keys for compliance requirements
- ElastiCache in-transit encryption (if needed)
- TLS between ALB and Web EC2 (if compliance mandates)
- CloudTrail encryption for audit logs

### Not Recommended
- Custom encryption libraries
- Manual key rotation
- Encryption of internal payloads
- TLS for performance-sensitive paths

---

## 10. Troubleshooting

### HTTPS Not Working
- Verify ACM certificate is issued (not pending validation)
- Check certificate covers domain name
- Ensure Route53/DNS points to ALB
- Verify security group allows port 443

### EBS Encryption Issues
- Cannot disable encryption after creation
- Existing volumes must be recreated to enable encryption
- AMIs inherit encryption state

### RDS Encryption Issues
- Cannot enable encryption on existing database
- Must create new encrypted database and migrate data
- Encryption state cannot be changed after creation

---

*Last Updated: January 7, 2026*  
*Infrastructure: BuildIT Platform*  
*Managed By: Terraform*
