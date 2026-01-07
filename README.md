# BuildIT Infrastructure - Terraform Architecture

## Project Overview

This Terraform project provisions a complete AWS infrastructure for the BuildIT platform, implementing a multi-tier architecture with web servers, execution engines, database services, and caching layers. The infrastructure is designed for high availability, scalability, and security, following AWS best practices for network isolation and defense-in-depth strategies.

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Network Architecture](#network-architecture)
3. [Compute Resources](#compute-resources)
4. [Load Balancing](#load-balancing)
5. [Data Layer](#data-layer)
6. [Security Architecture](#security-architecture)
7. [Auto Scaling Configuration](#auto-scaling-configuration)
8. [Encryption Strategy](#encryption-strategy)
9. [Infrastructure Components](#infrastructure-components)
10. [Variables and Configuration](#variables-and-configuration)
11. [Deployment Instructions](#deployment-instructions)
12. [Outputs](#outputs)
13. [Cost Optimization](#cost-optimization)

## Architecture Overview

The infrastructure implements a three-tier architecture with the following layers:

1. **Presentation Tier**: Application Load Balancer in public subnets
2. **Application Tier**: Web EC2 instances and Turbo execution engines in private subnets
3. **Data Tier**: RDS PostgreSQL and ElastiCache Valkey in database subnets

### High-Level Architecture Diagram

```
Internet
   |
   v
[Application Load Balancer] -----> [Web EC2 Auto Scaling Group]
   (Public Subnets)                  (Private Subnets)
                                            |
                                            v
                                   [Network Load Balancer] -----> [Turbo EC2 Auto Scaling Group]
                                     (Private Subnets)                  (Private Subnets)
                                                                            |
                                                                            v
                                                           [RDS PostgreSQL] + [ElastiCache Valkey]
                                                                     (Database Subnets)
```

## Network Architecture

### VPC Configuration

- **CIDR Block**: 10.0.0.0/16 (65,536 IP addresses)
- **DNS Support**: Enabled
- **DNS Hostnames**: Enabled
- **Availability Zones**: 2 (ap-south-1a, ap-south-1b) for high availability

### Subnet Design

The VPC is divided into three subnet tiers across two availability zones:

#### Public Subnets (Internet-Facing)
- **Purpose**: Host internet-facing load balancers and NAT gateways
- **CIDR Blocks**: 10.0.1.0/24 (AZ-1a), 10.0.2.0/24 (AZ-1b)
- **Total IPs**: 512 addresses (254 usable per subnet)
- **Internet Access**: Direct via Internet Gateway
- **Resources**: ALB, NAT Gateways

#### Private Subnets (Application Tier)
- **Purpose**: Host EC2 instances and internal load balancers
- **CIDR Blocks**: 10.0.11.0/24 (AZ-1a), 10.0.12.0/24 (AZ-1b)
- **Total IPs**: 512 addresses (254 usable per subnet)
- **Internet Access**: Outbound only via NAT Gateway
- **Resources**: Web EC2 instances, Turbo execution engines, Internal NLB

#### Database Subnets (Data Tier)
- **Purpose**: Host RDS and ElastiCache clusters
- **CIDR Blocks**: 10.0.21.0/24 (AZ-1a), 10.0.22.0/24 (AZ-1b)
- **Total IPs**: 512 addresses (254 usable per subnet)
- **Internet Access**: None (fully isolated)
- **Resources**: RDS PostgreSQL, ElastiCache Valkey

### Routing Configuration

#### Internet Gateway
- Provides internet access for public subnets
- Attached to VPC for public subnet routing

#### NAT Gateways
- **Count**: 2 (one per availability zone for high availability)
- **Purpose**: Enable private subnet instances to access internet for updates
- **Elastic IPs**: Static public IPs assigned to each NAT Gateway
- **Traffic Flow**: Private instances → NAT Gateway → Internet Gateway

#### Route Tables

1. **Public Route Table**
   - Routes all traffic (0.0.0.0/0) to Internet Gateway
   - Associated with both public subnets

2. **Private Route Tables** (2 total, one per AZ)
   - Routes all traffic (0.0.0.0/0) to respective NAT Gateway
   - Enables outbound internet access for package downloads
   - Associated with respective private subnets

3. **Database Route Table**
   - No internet routes (fully isolated)
   - Local VPC traffic only
   - Associated with both database subnets

## Compute Resources

### Web EC2 Instances

**Purpose**: Host the web application servers that handle user requests

**Configuration**:
- **Instance Type**: t4g.medium (configurable)
- **AMI**: Amazon Linux 2023 ARM64
- **Storage**: 24 GB GP3 EBS volume (encrypted)
- **Placement**: Private subnets across multiple AZs
- **Monitoring**: CloudWatch detailed monitoring enabled

**Auto Scaling**:
- **Minimum**: 1 instance (baseline)
- **Maximum**: 8 instances (peak load)
- **Desired**: 1 instance (initial)
- **Health Check**: ELB health checks
- **Grace Period**: 300 seconds

**User Data Script**:
```bash
#!/bin/bash
yum update -y
yum install -y httpd
systemctl start httpd
systemctl enable httpd
INSTANCE_ID=$(ec2-metadata --instance-id | cut -d " " -f 2)
echo "<h1>Web Server $INSTANCE_ID</h1>" > /var/www/html/index.html
echo "OK" > /var/www/html/health
```

**Connectivity**:
- Inbound: HTTP from ALB only (port 80)
- Outbound: PostgreSQL to RDS (port 5432), execution requests to NLB (port 8080), HTTPS for package downloads

### Turbo EC2 Instances

**Purpose**: Execute code and processing tasks requested by web servers

**Configuration**:
- **Instance Type**: c8g.xlarge (configurable)
- **AMI**: Amazon Linux 2023 ARM64
- **Storage**: 24 GB GP3 EBS volume (encrypted)
- **Placement**: Private subnets across multiple AZs
- **Monitoring**: CloudWatch detailed monitoring enabled

**Auto Scaling**:
- **Minimum**: 1 instance (baseline)
- **Maximum**: 8 instances (peak load)
- **Desired**: 1 instance (initial)
- **Health Check**: ELB health checks
- **Grace Period**: 300 seconds

**User Data Script**:
```bash
#!/bin/bash
yum update -y
yum install -y python3 docker
systemctl start docker
systemctl enable docker
mkdir -p /opt/turbo
INSTANCE_ID=$(ec2-metadata --instance-id | cut -d " " -f 2)
echo "Turbo Execution Node $INSTANCE_ID" > /opt/turbo/info.txt
```

**Connectivity**:
- Inbound: TCP from NLB (port 8080)
- Outbound: PostgreSQL to RDS (port 5432), Valkey to ElastiCache (port 6379), HTTPS for package downloads

## Load Balancing

### Application Load Balancer (ALB)

**Purpose**: Distribute HTTP/HTTPS traffic to web servers

**Configuration**:
- **Type**: Application Load Balancer (Layer 7)
- **Scheme**: Internet-facing
- **Subnets**: Both public subnets (multi-AZ)
- **Security**: ALB security group
- **Features**: HTTP/2 enabled, deletion protection disabled

**Listeners**:

1. **HTTP Listener (Port 80)**
   - Always enabled
   - Forwards traffic to Web target group
   - Used for development or as redirect target

2. **HTTPS Listener (Port 443)**
   - Conditional (requires ACM certificate)
   - SSL Policy: ELBSecurityPolicy-TLS13-1-2-2021-06
   - Supports TLS 1.2 and TLS 1.3
   - Forwards traffic to Web target group

**Target Group**:
- **Name**: buildit-web-tg
- **Port**: 80
- **Protocol**: HTTP
- **Health Check Path**: /health
- **Health Check Interval**: 30 seconds
- **Healthy Threshold**: 2 checks
- **Unhealthy Threshold**: 2 checks
- **Deregistration Delay**: 30 seconds

### Network Load Balancer (NLB)

**Purpose**: Distribute TCP traffic from Web servers to Turbo execution engines

**Configuration**:
- **Type**: Network Load Balancer (Layer 4)
- **Scheme**: Internal (VPC-only)
- **Subnets**: Both private subnets (multi-AZ)
- **Protocol**: TCP
- **Port**: 8080 (configurable)

**Target Group**:
- **Name**: buildit-turbo-tg
- **Port**: 8080
- **Protocol**: TCP
- **Health Check Protocol**: TCP
- **Health Check Interval**: 30 seconds
- **Healthy Threshold**: 2 checks
- **Unhealthy Threshold**: 2 checks
- **Deregistration Delay**: 30 seconds

**Design Rationale**:
- NLB chosen for low latency and high throughput for execution traffic
- Internal scheme ensures execution service is not exposed to internet
- TCP-based health checks for simple connectivity verification
- Preserves source IP addresses for logging
- Only accessible from Web EC2 instances within VPC

## Data Layer

### RDS PostgreSQL

**Purpose**: Primary relational database for application data and execution metadata

**Configuration**:
- **Engine**: PostgreSQL 15.4
- **Instance Class**: db.t4g.micro
- **Storage**: 20 GB GP3 (auto-scaling enabled up to 100 GB)
- **Encryption**: Enabled (AES-256, AWS-managed key)
- **Multi-AZ**: Enabled for high availability
- **Backup Retention**: 30 days
- **Public Access**: Disabled

**High Availability**:
- Multi-AZ deployment with automatic failover
- Synchronous replication to standby instance in different AZ
- Automatic failover in case of primary instance failure
- Failover time: typically 1-2 minutes

**Backup Strategy**:
- Automated daily backups with 30-day retention
- Point-in-time recovery enabled (up to 30 days)
- Transaction logs backed up every 5 minutes
- Backups encrypted automatically

**Database Configuration**:
- **Database Name**: buildit_db
- **Master Username**: buildit_admin (sensitive)
- **Master Password**: Defined in terraform.tfvars (sensitive)
- **Port**: 5432 (PostgreSQL default)

**Connectivity**:
- Accessible only from Web EC2 and Turbo EC2 security groups
- No public internet access
- VPC-internal endpoint

### ElastiCache Valkey (Redis)

**Purpose**: In-memory caching layer for session data, execution results, and temporary storage

**Configuration**:
- **Engine**: Redis 7.0 (Valkey-compatible)
- **Node Type**: cache.r7g.large
- **Number of Nodes**: 2 (primary + replica)
- **Replication**: Enabled
- **Automatic Failover**: Enabled
- **Port**: 6379 (Redis default)

**Encryption**:
- **At Rest**: Enabled (AES-256, AWS-managed key)
- **In Transit**: Not enabled (internal VPC traffic only)

**High Availability**:
- Primary node for writes, replica node for reads
- Automatic failover to replica if primary fails
- Multi-AZ placement for disaster recovery

**Use Cases**:
- Session management for web servers
- Caching execution results
- Queue management for asynchronous tasks
- Temporary data storage

**Connectivity**:
- Accessible only from Turbo EC2 security group
- No public internet access
- VPC-internal endpoint

## Security Architecture

### Security Groups

Security groups implement a zero-trust, least-privilege access model with explicit allow rules.

#### ALB Security Group
**Inbound Rules**:
- Port 80 (HTTP) from 0.0.0.0/0
- Port 443 (HTTPS) from 0.0.0.0/0

**Outbound Rules**:
- Port 80 (HTTP) to Web EC2 security group only

#### Web EC2 Security Group
**Inbound Rules**:
- Port 80 (HTTP) from ALB security group only

**Outbound Rules**:
- Port 5432 (PostgreSQL) to RDS security group
- Port 8080 (execution service) to Turbo EC2 security group (via internal NLB)
- Port 443 (HTTPS) to 0.0.0.0/0 (package downloads)

#### Turbo EC2 Security Group
**Inbound Rules**:
- Port 8080 (execution service) from Web EC2 security group (via internal NLB)

**Outbound Rules**:
- Port 5432 (PostgreSQL) to RDS security group
- Port 6379 (Valkey) to ElastiCache security group
- Port 443 (HTTPS) to 0.0.0.0/0 (package downloads)

#### RDS Security Group
**Inbound Rules**:
- Port 5432 (PostgreSQL) from Web EC2 security group
- Port 5432 (PostgreSQL) from Turbo EC2 security group

**Outbound Rules**:
- All traffic allowed (no outbound connectivity required)

#### ElastiCache Security Group
**Inbound Rules**:
- Port 6379 (Valkey/Redis) from Turbo EC2 security group only

**Outbound Rules**:
- All traffic allowed (no outbound connectivity required)

### Network Isolation Strategy

**Defense in Depth Layers**:

1. **Network Segmentation**: Three-tier subnet design isolates workloads
2. **Security Groups**: Stateful firewall rules control traffic flow
3. **Route Tables**: Control outbound internet access per subnet tier
4. **No Public IPs**: All application instances have private IPs only
5. **NAT Gateways**: Controlled outbound access for updates

**Traffic Flow Rules**:
- Internet traffic enters only through ALB
- Application tier cannot be accessed directly from internet
- Internal NLB provides secure Web-to-Turbo communication
- Database tier has no internet routes
- All inter-tier communication uses security group references
- No hardcoded IP addresses in security rules

## Auto Scaling Configuration

### Scheduled Scaling Strategy

Both Web and Turbo auto scaling groups implement scheduled scaling to optimize costs during predictable traffic patterns.

#### Web EC2 Scheduled Scaling

**Scale Up to Peak**:
- **Schedule**: 00:00 UTC Monday-Saturday (cron: `0 0 * * 1-6`)
- **Action**: Scale to maximum capacity (8 instances)
- **Use Case**: Anticipated high traffic periods

**Scale Down to Baseline**:
- **Schedule**: 08:00 UTC Monday-Saturday (cron: `0 8 * * 1-6`)
- **Action**: Scale to minimum capacity (1 instance)
- **Use Case**: Return to baseline after peak period

#### Turbo EC2 Scheduled Scaling

**Scale Up to Peak**:
- **Schedule**: 00:00 UTC Monday-Saturday (cron: `0 0 * * 1-6`)
- **Action**: Scale to maximum capacity (8 instances)
- **Use Case**: Match web server capacity for execution requests

**Scale Down to Baseline**:
- **Schedule**: 08:00 UTC Monday-Saturday (cron: `0 8 * * 1-6`)
- **Action**: Scale to minimum capacity (1 instance)
- **Use Case**: Return to baseline after peak period

### Health Checks

**Web Auto Scaling Group**:
- **Type**: ELB health checks
- **Grace Period**: 300 seconds (5 minutes)
- **Replacement**: Automatic for unhealthy instances
- **Health Check Path**: /health endpoint

**Turbo Auto Scaling Group**:
- **Type**: ELB health checks
- **Grace Period**: 300 seconds (5 minutes)
- **Replacement**: Automatic for unhealthy instances
- **Health Check**: TCP connection test on port 8080

### Launch Templates

Both instance types use launch templates for consistent, immutable instance configuration:

**Benefits**:
- Version control for instance configurations
- Immutable infrastructure pattern
- Easy rollback to previous configurations
- Consistent deployments across environments

## Encryption Strategy

The infrastructure implements encryption at rest and in transit following AWS best practices.

### Encryption in Transit

**Public Trust Boundary**:
- **Client to ALB**: HTTPS with TLS 1.2/1.3
- **SSL Policy**: ELBSecurityPolicy-TLS13-1-2-2021-06
- **Certificate**: AWS Certificate Manager (ACM)
- **Purpose**: Protect credentials and sensitive data from internet threats

**Internal Communication**:
- **ALB to Web EC2**: Plain HTTP (VPC-internal)
- **Web to NLB to Turbo**: Plain TCP (VPC-internal)
- **Rationale**: Private subnets protected by security groups, no internet exposure

### Encryption at Rest

**EBS Volumes**:
- **Status**: Enabled for all EC2 instances
- **Algorithm**: AES-256
- **Key Management**: AWS-managed KMS keys
- **Coverage**: Root volumes for Web and Turbo instances

**RDS PostgreSQL**:
- **Status**: Enabled
- **Algorithm**: AES-256 (transparent encryption)
- **Key Management**: AWS-managed KMS keys
- **Coverage**: Database files, automated backups, snapshots, logs

**ElastiCache Valkey**:
- **At Rest**: Enabled
- **In Transit**: Not enabled (internal VPC only)
- **Algorithm**: AES-256
- **Key Management**: AWS-managed KMS keys

### Security Rationale

**Why Encrypt Public Ingress?**
- Protects against man-in-the-middle attacks
- Prevents credential theft over public internet
- Ensures data privacy during transmission

**Why Not Encrypt Internal Traffic?**
- VPC isolation provides network-level security
- Security groups enforce strict access controls
- Performance optimization for high-throughput execution path
- Reduced operational complexity

**Quote from Architecture Guidelines**:
> "Encrypt at the edge and at storage. Do not encrypt inside trusted execution paths."

## Infrastructure Components

### Resource Count Summary

| Resource Type | Count | Purpose |
|--------------|-------|---------|
| VPC | 1 | Network isolation |
| Internet Gateway | 1 | Public subnet internet access |
| NAT Gateway | 2 | Private subnet outbound access |
| Elastic IP | 2 | Static IPs for NAT Gateways |
| Public Subnets | 2 | Load balancers |
| Private Subnets | 2 | Application instances |
| Database Subnets | 2 | Data tier |
| Route Tables | 4 | Traffic routing control |
| Security Groups | 5 | Firewall rules |
| Security Group Rules | 18 | Explicit access policies |
| Application Load Balancer | 1 | Web traffic distribution |
| Network Load Balancer | 1 | Execution traffic distribution |
| ALB Target Groups | 1 | Web instance registration |
| NLB Target Groups | 1 | Turbo instance registration |
| Launch Templates | 2 | Instance configurations |
| Auto Scaling Groups | 2 | Dynamic scaling |
| Scheduled Scaling Actions | 4 | Cost optimization |
| RDS Instance | 1 | PostgreSQL database |
| RDS Subnet Group | 1 | Multi-AZ placement |
| ElastiCache Replication Group | 1 | Valkey cluster |
| ElastiCache Subnet Group | 1 | Multi-AZ placement |

## Variables and Configuration

### Required Variables

These variables must be configured before deployment:

```hcl
# Database password (SENSITIVE)
db_password = "your-secure-password-here"

# ACM certificate for HTTPS (optional, but recommended for production)
acm_certificate_arn = "arn:aws:acm:region:account:certificate/cert-id"
```

### Key Configurable Variables

#### Network Configuration
- `aws_region`: AWS region (default: ap-south-1)
- `vpc_cidr`: VPC CIDR block (default: 10.0.0.0/16)
- `availability_zones`: AZs to use (default: ap-south-1a, ap-south-1b)
- `enable_nat_gateway`: Enable NAT for private subnets (default: true)

#### Compute Configuration
- `web_instance_type`: Web EC2 instance type (default: t2.micro)
- `turbo_instance_type`: Turbo EC2 instance type (default: t2.micro)
- `ebs_volume_size`: EBS volume size in GB (default: 24)
- `enable_detailed_monitoring`: CloudWatch detailed monitoring (default: true)

#### Auto Scaling Configuration
- `web_instance_count_min`: Minimum web instances (default: 1)
- `web_instance_count_max`: Maximum web instances (default: 8)
- `web_instance_count_desired`: Initial web instances (default: 1)
- `turbo_instance_count_min`: Minimum turbo instances (default: 1)
- `turbo_instance_count_max`: Maximum turbo instances (default: 8)
- `turbo_instance_count_desired`: Initial turbo instances (default: 1)

#### Database Configuration
- `db_instance_class`: RDS instance class (default: db.t4g.micro)
- `db_name`: Database name (default: buildit_db)
- `db_username`: Master username (default: buildit_admin)

#### Cache Configuration
- `elasticache_node_type`: ElastiCache node type (default: cache.r7g.large)
- `elasticache_num_nodes`: Number of cache nodes (default: 2)

#### Scaling Schedule Configuration
- `peak_schedule_start`: Scale up cron (default: 0 0 * * 1-6)
- `peak_schedule_end`: Scale down cron (default: 0 8 * * 1-6)

#### Security Configuration
- `ssh_key_name`: SSH key pair name (default: "", optional)
- `turbo_execution_port`: Turbo service port (default: 8080)
- `acm_certificate_arn`: ACM certificate for HTTPS (default: "")

#### Tagging
- `project_name`: Project name for resource naming (default: buildit)
- `tags`: Common tags for all resources

## Deployment Instructions

### Prerequisites

1. **AWS Account**: Active AWS account with appropriate permissions
2. **AWS CLI**: Installed and configured with credentials
3. **Terraform**: Version 1.0 or higher installed
4. **ACM Certificate**: SSL certificate created in AWS Certificate Manager (for HTTPS)

### Step 1: Configure Variables

Create or update `terraform.tfvars`:

```hcl
# Required
db_password = "your-very-secure-password"

# Recommended for production
acm_certificate_arn = "arn:aws:acm:ap-south-1:123456789012:certificate/abc123"

# Optional customizations
project_name = "buildit"
aws_region = "ap-south-1"
web_instance_type = "t3.small"
turbo_instance_type = "t3.medium"
```

### Step 2: Initialize Terraform

```bash
cd TerraformPractice
terraform init
```

This downloads the AWS provider and initializes the backend.

### Step 3: Validate Configuration

```bash
terraform validate
```

Ensures all configuration files are syntactically correct.

### Step 4: Plan Deployment

```bash
terraform plan
```

Review the execution plan to see what resources will be created.

### Step 5: Deploy Infrastructure

```bash
terraform apply
```

Type `yes` when prompted to confirm deployment.

**Deployment Time**: Approximately 10-15 minutes

### Step 6: Retrieve Outputs

```bash
terraform output
```

This displays important endpoints and resource identifiers.

## Outputs

The infrastructure provides the following outputs after deployment:

### Network Outputs
- `vpc_id`: VPC identifier
- `public_subnet_ids`: Public subnet identifiers
- `private_subnet_ids`: Private subnet identifiers
- `db_subnet_ids`: Database subnet identifiers

### Load Balancer Outputs
- `alb_dns_name`: Application Load Balancer DNS name
- `nlb_dns_name`: Network Load Balancer DNS name
- `alb_url`: HTTP URL to access web application
- `nlb_url`: TCP URL to access execution service

### Database Outputs
- `rds_endpoint`: PostgreSQL connection endpoint (host:port)
- `rds_database_name`: Database name
- `elasticache_endpoint`: Valkey primary endpoint address

### Auto Scaling Outputs
- `web_asg_name`: Web Auto Scaling Group name
- `turbo_asg_name`: Turbo Auto Scaling Group name

## Cost Optimization

### Cost Optimization Strategies

1. **Scheduled Scaling**: Reduces instance count during off-peak hours
2. **Reserved Instances**: Purchase 1-year or 3-year reservations for baseline capacity
3. **Right-Sizing**: Monitor CloudWatch metrics and adjust instance types
4. **NAT Gateway Consolidation**: Use single NAT Gateway for development environments
5. **ElastiCache Nodes**: Reduce to 1 node for non-production environments
6. **RDS Multi-AZ**: Disable for development environments
7. **Spot Instances**: Use for non-critical workloads (not implemented)

### Potential Savings

- **Development Environment**: ~$140/month (disable Multi-AZ, single NAT, smaller instances)
- **Reserved Instances**: 30-40% savings on compute costs
- **Spot Instances**: Up to 90% savings for fault-tolerant workloads

## Maintenance and Operations

### Monitoring

**CloudWatch Metrics**:
- EC2 instance CPU, memory, disk utilization
- ALB request count, target response time, HTTP status codes
- NLB active connections, processed bytes
- RDS CPU, storage, connections, read/write latency
- ElastiCache CPU, memory, cache hits/misses

**Recommended Alarms**:
- ALB 5xx errors > 10 per minute
- RDS CPU utilization > 80%
- ElastiCache memory utilization > 90%
- Auto Scaling Group unhealthy instances > 0

### Backup Strategy

**Automated Backups**:
- RDS automated backups: 30-day retention
- RDS snapshots: Manual snapshots for major changes
- EBS snapshots: Not automated (consider AWS Backup service)

### Disaster Recovery

**RDS Multi-AZ**:
- Automatic failover to standby in different AZ
- Recovery Time Objective (RTO): 1-2 minutes
- Recovery Point Objective (RPO): Near zero (synchronous replication)

**ElastiCache**:
- Automatic failover to replica node
- RTO: 1-2 minutes
- RPO: Possible data loss (asynchronous replication)

**Application Tier**:
- Stateless design enables easy recovery
- Auto Scaling replaces unhealthy instances automatically
- RTO: 5 minutes (instance launch time)

### Security Updates

**EC2 Instances**:
- User data scripts install latest packages on launch
- Implement regular AMI updates with patched OS
- Use AWS Systems Manager for patch management

**RDS and ElastiCache**:
- AWS manages OS and engine patches
- Configure maintenance windows for updates
- Minor version updates: Automatic
- Major version updates: Manual with testing

## Troubleshooting

### Common Issues

**Issue**: HTTPS listener not created
**Solution**: Ensure `acm_certificate_arn` variable is set with valid ACM certificate

**Issue**: EC2 instances not registering with target groups
**Solution**: Check security group rules, verify health check endpoint returns 200 OK

**Issue**: No internet access from private instances
**Solution**: Verify NAT Gateway is enabled (`enable_nat_gateway = true`)

**Issue**: RDS connection refused
**Solution**: Verify security group allows traffic from application security groups

**Issue**: High costs
**Solution**: Review instance counts, consider reserved instances, disable NAT Gateway in dev

### Verification Commands

```bash
# Check VPC
aws ec2 describe-vpcs --filters "Name=tag:Name,Values=buildit-vpc"

# Check running instances
aws ec2 describe-instances --filters "Name=tag:Name,Values=buildit-*-ec2" --query 'Reservations[*].Instances[*].[InstanceId,State.Name,PrivateIpAddress]'

# Check ALB health
aws elbv2 describe-target-health --target-group-arn $(terraform output -raw web_target_group_arn)

# Check RDS status
aws rds describe-db-instances --db-instance-identifier buildit-postgres --query 'DBInstances[0].[DBInstanceStatus,Endpoint.Address]'

# Check ElastiCache status
aws elasticache describe-replication-groups --replication-group-id buildit-cache --query 'ReplicationGroups[0].[Status,PrimaryEndpoint.Address]'
```

## Support and Documentation

### Additional Resources

- [Terraform AWS Provider Documentation](https://registry.terraform.io/providers/hashicorp/aws/latest/docs)
- [AWS Well-Architected Framework](https://aws.amazon.com/architecture/well-architected/)
- [AWS Security Best Practices](https://docs.aws.amazon.com/security/)
- [Encryption Implementation Guide](ENCRYPTION.md)
- [Encryption Quick Reference](ENCRYPTION-QUICK-REF.md)

### Project Files

- [main.tf](main.tf): Main infrastructure configuration
- [variables.tf](variables.tf): Input variable definitions
- [output.tf](output.tf): Output value definitions
- [terraform.tfvars](terraform.tfvars): Variable value assignments
- [ENCRYPTION.md](ENCRYPTION.md): Detailed encryption documentation

## Conclusion

This Terraform project implements a production-ready, highly available, and secure AWS infrastructure for the BuildIT platform. The architecture follows AWS best practices for network isolation, security, encryption, and cost optimization while maintaining flexibility for future growth and enhancements.
