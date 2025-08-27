# proTecht Database System

## Overview

The proTecht database system provides comprehensive storage and management of AWS infrastructure data for compliance analysis. It uses SQLite for simplicity and portability while maintaining enterprise-grade data structures.

## Features

### Data Storage
- **AWS Infrastructure Data**: Complete AWS service configurations
- **Compliance Controls**: Framework-specific control mappings
- **Analysis Results**: Historical compliance assessments
- **User Sessions**: Upload and analysis tracking

### Database Schema
- **AWS Services**: EC2, S3, RDS, IAM, VPC, Lambda, CloudTrail, etc.
- **Compliance Frameworks**: FedRAMP, NIST, ISO, PCI DSS
- **Control Mappings**: Framework-to-AWS service relationships
- **Analysis History**: Timestamped compliance results

## Quick Start

### 1. Initialize Database
```bash
python database.py
```

### 2. Load AWS Data
```bash
python load_aws_data.py
```

### 3. Verify Data
```bash
python db_manager.py --stats
```

## Database Management

### View Statistics
```bash
python db_manager.py --stats
```

### Show Sample Data
```bash
python db_manager.py --sample
```

### Backup Database
```bash
python db_manager.py --backup
```

### Reset Database
```bash
python db_manager.py --reset
```

### Reload Data
```bash
python db_manager.py --reload
```

## Integration

### In Your Code
```python
from database import ProTechtDatabase

# Initialize database
db = ProTechtDatabase()

# Get AWS data
aws_data = db.get_aws_data()

# Get specific service data
ec2_data = db.get_aws_data()['ec2']
s3_data = db.get_aws_data()['s3']
```

### Error Handling
```python
try:
    aws_data = db.get_aws_data()
except Exception as e:
    print(f"Database error, using fallback data: {e}")
    # Use fallback data
```

## Schema Examples

### AWS EC2 Instances
```sql
CREATE TABLE ec2_instances (
    id TEXT PRIMARY KEY,
    instance_type TEXT,
    state TEXT,
    security_groups TEXT,
    iam_role TEXT,
    encryption TEXT,
    monitoring TEXT,
    tags TEXT
);
```

### S3 Buckets
```sql
CREATE TABLE s3_buckets (
    name TEXT PRIMARY KEY,
    encryption TEXT,
    versioning TEXT,
    public_access TEXT,
    object_lock TEXT,
    lifecycle_policy TEXT,
    tags TEXT
);
```

## Benefits

### Performance
- **Fast Queries**: Optimized SQLite queries
- **Efficient Storage**: Compressed data structures
- **Quick Startup**: Minimal initialization time

### Reliability
- **Data Integrity**: ACID compliance
- **Backup Support**: Easy backup and restore
- **Error Recovery**: Graceful fallback mechanisms

### Flexibility
- **Easy Migration**: Simple schema updates
- **Custom Extensions**: Add new services easily
- **Framework Support**: Extensible compliance mappings

## Security

### Data Protection
- **No Sensitive Data**: Only configuration information
- **Local Storage**: Data stays on your system
- **Access Control**: File-based permissions

### Best Practices
- **Regular Backups**: Automated backup scheduling
- **Version Control**: Schema version tracking
- **Validation**: Data integrity checks

## Troubleshooting

### Common Issues

**Database not found**
```bash
python database.py  # Reinitialize database
```

**Data loading failed**
```bash
python load_aws_data.py  # Reload data
```

**Permission errors**
```bash
chmod 644 protecht.db  # Fix permissions
```

### Debug Mode
```bash
python db_manager.py --debug
```

## Support

For database issues:
1. Check the logs in `database.log`
2. Run `python db_manager.py --debug`
3. Verify file permissions
4. Check available disk space

---

**proTecht Database System - Enterprise-grade data management for compliance automation** 