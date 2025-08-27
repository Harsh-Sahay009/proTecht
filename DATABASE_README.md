# proTecht Database System

## Overview

The proTecht database system provides a comprehensive SQLite database for storing AWS infrastructure data used in compliance analysis. This system replaces the hardcoded mock data with a scalable, persistent database solution.

## Database Structure

### Core Tables (35+ tables)

The database includes tables for all major AWS services:

#### Identity & Access Management
- `iam_users` - User accounts and MFA status
- `iam_roles` - IAM roles and permissions
- `iam_password_policy` - Password policy settings
- `sso` - Single Sign-On configuration

#### Storage & Data
- `s3_buckets` - S3 bucket configurations and encryption
- `kms_keys` - KMS key management and rotation
- `dynamodb_tables` - DynamoDB table encryption
- `efs_file_systems` - EFS file system encryption
- `rds_instances` - RDS database instances

#### Security & Compliance
- `cloudtrail_trails` - CloudTrail logging configuration
- `config_rules` - AWS Config compliance rules
- `config_conformance_packs` - Conformance pack status
- `guardduty` - GuardDuty findings and detectors
- `security_hub` - Security Hub standards and findings
- `macie_jobs` - Macie data discovery jobs
- `inspector2` - Inspector vulnerability findings

#### Compute & Networking
- `eks_clusters` - EKS Kubernetes clusters
- `ecs_clusters` - ECS container clusters
- `vpc` - VPC configuration and flow logs
- `security_groups` - Security group rules
- `api_gateway` - API Gateway endpoints
- `waf` - WAF web ACLs and rules
- `cloudfront` - CloudFront distributions

#### Monitoring & Operations
- `cloudwatch` - CloudWatch alarms and metrics
- `lambda` - Lambda functions and concurrency
- `codebuild` - CodeBuild projects and builds
- `codepipeline` - CodePipeline pipelines
- `ssm_patch` - SSM patch management
- `eventbridge_rules` - EventBridge rules and targets

#### Infrastructure
- `backup` - AWS Backup vaults and resources
- `route53` - Route53 hosted zones and health checks
- `direct_connect` - Direct Connect connections
- `vpn` - VPN endpoints and sessions
- `detective` - Detective graph and member accounts

## Quick Start

### 1. Initialize Database
```bash
# The database is automatically initialized when you run the application
python3 main.py
```

### 2. Load Sample Data
```bash
# Load comprehensive AWS infrastructure data
python3 load_aws_data.py
```

### 3. Check Database Status
```bash
# View database statistics
python3 db_manager.py stats

# View sample data from a specific table
python3 db_manager.py sample iam_users
```

## Database Management

### Available Commands

```bash
# Show database statistics
python3 db_manager.py stats

# Show sample data from a table
python3 db_manager.py sample <table_name>

# Create database backup
python3 db_manager.py backup

# Reset database (clear all data)
python3 db_manager.py reset

# Reload AWS data
python3 db_manager.py reload
```

### Database Statistics

Current database contains:
- **35+ tables** covering all major AWS services
- **60+ records** of infrastructure data
- **Comprehensive coverage** of security controls
- **Real-time access** for compliance analysis

## Integration with Application

### Automatic Fallback
The application automatically uses the database when available, with graceful fallback to hardcoded data:

```python
def get_aws_data():
    """Get AWS data from database or fallback"""
    if db:
        try:
            return db.get_aws_data()
        except Exception as e:
            print(f"⚠️  Database error, using fallback data: {e}")
            return FALLBACK_AWS_DATA
    else:
        return FALLBACK_AWS_DATA
```

### Data Flow
1. **Database Query** → Retrieve AWS infrastructure data
2. **Compliance Analysis** → Compare SSP against database
3. **Real-time Results** → Generate compliance reports
4. **AI Recommendations** → Based on actual infrastructure

## Data Schema

### Example: IAM Users Table
```sql
CREATE TABLE iam_users (
    id INTEGER PRIMARY KEY,
    username TEXT UNIQUE,
    mfa_enabled BOOLEAN,
    last_login TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

### Example: S3 Buckets Table
```sql
CREATE TABLE s3_buckets (
    id INTEGER PRIMARY KEY,
    bucket_name TEXT UNIQUE,
    encryption TEXT,
    object_lock_mode TEXT,
    retention_days INTEGER,
    public_access_block BOOLEAN,
    kms_key_id TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

## Benefits

### 1. **Scalability**
- Support for multiple AWS accounts
- Easy data updates and modifications
- Efficient querying and filtering

### 2. **Reliability**
- Persistent data storage
- Automatic backups and recovery
- Data integrity constraints

### 3. **Flexibility**
- Easy to extend with new services
- Support for custom data types
- JSON serialization for complex data

### 4. **Performance**
- Fast query execution
- Indexed fields for quick lookups
- Optimized for compliance analysis

## Security Features

### Data Protection
- SQLite database with file-level security
- No sensitive data in plain text
- Encrypted storage support

### Access Control
- Database-level access controls
- Backup and restore procedures
- Audit trail with timestamps

## Future Enhancements

### Planned Features
- **Multi-account support** - Multiple AWS accounts
- **Real-time sync** - Live AWS data integration
- **Advanced analytics** - Compliance trend analysis
- **Custom controls** - User-defined compliance rules
- **API endpoints** - RESTful database access

### Scalability Improvements
- **PostgreSQL migration** - For larger deployments
- **Connection pooling** - Improved performance
- **Caching layer** - Redis integration
- **Data versioning** - Historical compliance tracking

## Troubleshooting

### Common Issues

1. **Database not found**
   ```bash
   # Reinitialize database
   python3 load_aws_data.py
   ```

2. **Permission errors**
   ```bash
   # Check file permissions
   chmod 644 protecht.db
   ```

3. **Data corruption**
   ```bash
   # Restore from backup
   python3 db_manager.py backup
   python3 db_manager.py reset
   python3 load_aws_data.py
   ```

### Performance Optimization
- Regular database maintenance
- Index optimization for large datasets
- Query optimization for complex compliance checks

## Support

For database-related issues:
1. Check the database statistics: `python3 db_manager.py stats`
2. Verify data integrity: `python3 db_manager.py sample <table>`
3. Create backup before modifications: `python3 db_manager.py backup`
4. Reset if needed: `python3 db_manager.py reset`

---

**Note**: This database system is designed for development and demonstration purposes. For production use, consider implementing additional security measures and using a more robust database system like PostgreSQL. 