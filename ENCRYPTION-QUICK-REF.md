# Quick Encryption Reference

## ✅ What IS Encrypted

| Component         | Type           | Algorithm | Key Management |
|-------------------|----------------|-----------|----------------|
| Client → ALB      | TLS 1.2/1.3    | N/A       | ACM            |
| Web EC2 EBS       | At Rest        | AES-256   | AWS KMS        |
| Turbo EC2 EBS     | At Rest        | AES-256   | AWS KMS        |
| RDS PostgreSQL    | At Rest        | AES-256   | AWS KMS        |
| ElastiCache       | At Rest        | AES-256   | AWS KMS        |

## ❌ What is NOT Encrypted

| Path                     | Reason                                      |
|--------------------------|---------------------------------------------|
| ALB → Web EC2            | Private VPC, optional only                  |
| Web EC2 → NLB → Turbo    | Private VPC, performance-sensitive          |
| Application payloads     | Unnecessary, handled at storage             |

## 🚀 Quick Setup

### 1. Get ACM Certificate ARN
```bash
aws acm list-certificates --region ap-south-1
```

### 2. Update terraform.tfvars
```hcl
acm_certificate_arn = "arn:aws:acm:ap-south-1:123456789012:certificate/abcd1234"
```

### 3. Deploy
```bash
terraform apply
```

## 🔍 Verification Commands

```bash
# Check ALB has HTTPS listener
terraform output alb_dns_name
curl -I https://YOUR_DOMAIN

# Verify EBS encryption
aws ec2 describe-volumes \
  --filters "Name=tag:Name,Values=buildit-*" \
  --query 'Volumes[*].Encrypted'

# Verify RDS encryption
aws rds describe-db-instances \
  --db-instance-identifier buildit-postgres \
  --query 'DBInstances[0].StorageEncrypted'

# Verify ElastiCache encryption
aws elasticache describe-replication-groups \
  --replication-group-id buildit-cache \
  --query 'ReplicationGroups[0].AtRestEncryptionEnabled'
```

## 📝 One-Line Summary

**"Encrypt at the edge (ALB) and at storage (EBS/RDS/Cache). Do not encrypt inside trusted execution paths."**

## 🎯 Key Points

1. **HTTPS is mandatory** at ALB (public trust boundary)
2. **All storage is encrypted** (EBS, RDS, ElastiCache)
3. **Internal traffic is plain** (private VPC, performance)
4. **AWS-managed keys** (no key management overhead)
5. **Zero cost** (encryption included with services)

---

See [ENCRYPTION.md](ENCRYPTION.md) for complete documentation.
