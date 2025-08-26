#!/usr/bin/env python3
"""
Load AWS infrastructure data into proTecht database
"""

from database import ProTechtDatabase
import json

# AWS infrastructure data
AWS_DATA = {
    "account_metadata": {
        "org_id": "o-abc123xyz",
        "master_payer_id": "123456789012",
        "regions": ["us-gov-west-1", "us-gov-east-1"]
    },
    "control_tower": {
        "version": "3.4",
        "enabled_guardrails": 42,
        "accounts_managed": 12
    },
    "iam": {
        "password_policy": {
            "MinimumPasswordLength": 14,
            "RequireSymbols": True,
            "RequireNumbers": True,
            "RequireUppercaseCharacters": True,
            "RequireLowercaseCharacters": True,
            "MaxPasswordAge": 60,
            "PasswordReusePrevention": 5
        },
        "users": [
            {"UserName": "alice", "MFA": True, "LastLogin": "2025-08-28"},
            {"UserName": "bob", "MFA": False, "LastLogin": "2025-06-01"},
            {"UserName": "charlie", "MFA": True, "LastLogin": "2025-08-15"},
            {"UserName": "david", "MFA": True, "LastLogin": "2025-08-20"},
            {"UserName": "root", "MFA": True, "LastLogin": "2025-07-30"}
        ],
        "inactive_user_disable_days": 30,
        "roles": [
            {"RoleName": "DevOps", "Permissions": ["EC2","S3"], "Boundary": "arn:aws:iam::aws:policy/PowerUserAccess"},
            {"RoleName": "SecurityAdmin", "Permissions": ["IAM","Config","SecurityHub"], "Boundary": None}
        ]
    },
    "sso": {
        "application_count": 8,
        "mfa_types": ["Virtual","Hardware","WebAuthn"],
        "federation": "Okta"
    },
    "s3": [
        {"Bucket": "central-logs", "Encryption": "AES256", "ObjectLockMode": "GOVERNANCE", "RetentionDays": 365, "PublicAccessBlock": True},
        {"Bucket": "tenant-artifacts", "Encryption": "aws:kms", "KmsKeyId": "alias/tenant-key", "PublicAccessBlock": True},
        {"Bucket": "dev-test-binaries", "Encryption": None, "PublicAccessBlock": False},
        {"Bucket": "pii-archive", "Encryption": "aws:kms", "KmsKeyId": "alias/pii-archive", "ObjectLockMode": "COMPLIANCE", "RetentionDays": 730, "PublicAccessBlock": True}
    ],
    "kms": [
        {"KeyId": "key-1111", "RotationEnabled": True, "Alias": "alias/prod-master"},
        {"KeyId": "key-2222", "RotationEnabled": False, "Alias": "alias/dev-nokeyrotate"},
        {"KeyId": "key-3333", "RotationEnabled": True, "Alias": "alias/pii-archive"}
    ],
    "cloudtrail": {
        "trails": [
            {"Name": "orgTrail", "MultiRegion": True, "LogFileValidation": True, "InsightSelectors": ["ApiCallRateInsight","ErrorRateInsight"]}
        ]
    },
    "config": {
        "rules": [
            {"Name": "phoenix-ac2-inactive", "ComplianceType": "COMPLIANT"},
            {"Name": "phoenix-s3-encryption", "ComplianceType": "NON_COMPLIANT"},
            {"Name": "phoenix-ssh-restricted", "ComplianceType": "COMPLIANT"}
        ],
        "conformance_packs": [
            {"Name": "CIS-1.4", "Status": "NON_COMPLIANT", "FailingRules": 6},
            {"Name": "NIST-800-53", "Status": "NON_COMPLIANT", "FailingRules": 12}
        ]
    },
    "guardduty": {
        "detector_count": 1,
        "findings": {"Critical": 0, "High": 2, "Medium": 7, "Low": 15}
    },
    "security_hub": {
        "standards": {
            "CIS AWS Foundations v1.4.0": "FAILED",
            "AWS Best Practices": "FAILED"
        },
        "open_findings": 22
    },
    "macie": {
        "jobs": [
            {"JobId": "j-abcd", "Status": "RUNNING", "S3BucketsScanned": 14},
            {"JobId": "j-efgh", "Status": "COMPLETE", "SensitiveFindings": 5}
        ]
    },
    "inspector2": {
        "last_run": "2025-08-29",
        "findings": {"Critical": 6, "High": 14, "Medium": 37, "Low": 120}
    },
    "eks": [
        {"Cluster": "gov-prod-eks", "OIDC": True, "IRSA": True, "K8sVersion": "1.29", "PublicAccess": False},
        {"Cluster": "gov-dev-eks", "OIDC": True, "IRSA": False, "K8sVersion": "1.27", "PublicAccess": True}
    ],
    "ecs": [
        {"Cluster": "gov-prod-ecs", "FargateTasks": 12, "EC2Tasks": 6},
        {"Cluster": "gov-dev-ecs", "FargateTasks": 5, "EC2Tasks": 2}
    ],
    "rds": [
        {"DBInstance": "prod-aurora-global", "Engine": "aurora-postgresql", "Encrypted": True, "MultiAZ": True},
        {"DBInstance": "dev-mysql", "Engine": "mysql", "Encrypted": False, "MultiAZ": False}
    ],
    "dynamodb": [
        {"Table": "Tenant-Meta", "Encrypted": True, "KmsKeyId": "alias/prod-master"},
        {"Table": "Dev-Flags", "Encrypted": False, "KmsKeyId": None}
    ],
    "efs": [
        {"FileSystemId": "fs-aaa111", "Encrypted": True, "KmsKeyId": "alias/prod-master"},
        {"FileSystemId": "fs-bbb222", "Encrypted": False}
    ],
    "backup": {
        "vault_name": "phoenix-backup-vault", "resources_protected": 128, "cross_region_copy": True, "vault_lock": "ON"
    },
    "vpc": {
        "flow_logs": True,
        "security_groups": [
            {"GroupId": "sg-aaa111", "OpenPorts": [22], "AllowedCidrs": ["10.0.0.0/16"]},
            {"GroupId": "sg-bbb222", "OpenPorts": [22, 3389], "AllowedCidrs": ["0.0.0.0/0"]}
        ],
        "nat_gateways": 4,
        "transit_gateway": {"attachments": 3}
    },
    "api_gateway": {
        "endpoints": [
            {"Stage": "prod", "ExecutionLogging": True},
            {"Stage": "dev", "ExecutionLogging": False}
        ]
    },
    "waf": {
        "web_acls": [{"Name": "phoenix-waf", "Rules": 15, "BlockedCount7d": 12000}]
    },
    "cloudfront": {
        "distributions": [
            {"Id": "E111AAA", "TLSPolicy": "TLSv1.2_2021", "WAFEnabled": True},
            {"Id": "E222BBB", "TLSPolicy": "TLSv1.2_2021", "WAFEnabled": False}
        ]
    },
    "ssm_patch": {
        "last_scan": "2025-08-28", "pending_critical": 5, "pending_high": 11
    },
    "eventbridge": {
        "rules": [
            {"Name": "gd-to-sh", "Target": "SecurityHub", "State": "ENABLED"},
            {"Name": "cve-to-jira", "Target": "Jira", "State": "ENABLED"}
        ]
    },
    "detective": {
        "graph_enabled": True, "member_accounts": 5
    },
    "codebuild": {
        "projects": 5, "failed_builds_last7d": 2, "passed": 120
    },
    "codepipeline": {
        "pipelines": 3, "failed_executions": 1
    },
    "lambda": {
        "functions": 45, "unreserved_concurrent_executions": 25
    },
    "cloudwatch": {
        "alarms": 32, "metrics_collected": 150
    },
    "route53": {
        "hosted_zones": 4, "health_checks": 8
    },
    "direct_connect": {
        "connections": 2, "locations": ["DC1", "DC2"]
    },
    "vpn": {
        "client_vpn_endpoints": 1, "active_sessions": 7
    }
}

def main():
    """Load AWS data into database"""
    print("🚀 Loading AWS infrastructure data into proTecht database...")
    
    try:
        # Initialize database
        db = ProTechtDatabase()
        
        # Load AWS data
        db.load_aws_data(AWS_DATA)
        
        print("✅ AWS data loaded successfully!")
        print("📊 Database contains comprehensive AWS infrastructure data")
        print("🔍 You can now use this data for compliance analysis")
        
    except Exception as e:
        print(f"❌ Error loading AWS data: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    exit(main()) 