#!/usr/bin/env python3
"""
Database management script for proTecht
"""

import sqlite3
import json
from database import ProTechtDatabase
import os

def show_database_stats():
    """Show database statistics"""
    db = ProTechtDatabase()
    conn = db.get_connection()
    cursor = conn.cursor()
    
    print("proTecht Database Statistics")
    print("=" * 50)
    
    tables = [
        'account_metadata', 'control_tower', 'iam_password_policy', 'iam_users', 'iam_roles',
        'sso', 's3_buckets', 'kms_keys', 'cloudtrail_trails', 'config_rules', 'config_conformance_packs',
        'guardduty', 'security_hub', 'macie_jobs', 'inspector2', 'eks_clusters', 'ecs_clusters',
        'rds_instances', 'dynamodb_tables', 'efs_file_systems', 'backup', 'vpc', 'security_groups',
        'api_gateway', 'waf', 'cloudfront', 'ssm_patch', 'eventbridge_rules', 'detective',
        'codebuild', 'codepipeline', 'lambda', 'cloudwatch', 'route53', 'direct_connect', 'vpn'
    ]
    
    total_records = 0
    for table in tables:
        try:
            cursor.execute(f'SELECT COUNT(*) FROM {table}')
            count = cursor.fetchone()[0]
            print(f"{table:25} : {count:3} records")
            total_records += count
        except Exception as e:
            print(f"{table:25} : ERROR - {e}")
    
    print("-" * 50)
    print(f"Total Records: {total_records}")
    
    conn.close()

def show_sample_data(table_name):
    """Show sample data from a specific table"""
    db = ProTechtDatabase()
    conn = db.get_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute(f'SELECT * FROM {table_name} LIMIT 5')
        rows = cursor.fetchall()
        
        if rows:
            print(f"📋 Sample data from {table_name}:")
            print("=" * 50)
            for i, row in enumerate(rows, 1):
                print(f"Record {i}:")
                for key in row.keys():
                    print(f"  {key}: {row[key]}")
                print()
        else:
            print(f"No data found in {table_name}")
            
    except Exception as e:
        print(f"Error querying {table_name}: {e}")
    
    conn.close()

def backup_database():
    """Create a backup of the database"""
    import shutil
    from datetime import datetime
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_name = f"protecht_backup_{timestamp}.db"
    
    try:
        shutil.copy2("protecht.db", backup_name)
        print(f"Database backed up to {backup_name}")
    except Exception as e:
        print(f"Backup failed: {e}")

def reset_database():
    """Reset the database (clear all data)"""
    db = ProTechtDatabase()
    db.clear_all_data()
    print("Database cleared")

def main():
    """Main function"""
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python3 db_manager.py [command]")
        print("Commands:")
        print("  stats                    - Show database statistics")
        print("  sample <table_name>      - Show sample data from table")
        print("  backup                   - Create database backup")
        print("  reset                    - Reset database (clear all data)")
        print("  reload                   - Reload AWS data from load_aws_data.py")
        return
    
    command = sys.argv[1]
    
    if command == "stats":
        show_database_stats()
    elif command == "sample" and len(sys.argv) > 2:
        show_sample_data(sys.argv[2])
    elif command == "backup":
        backup_database()
    elif command == "reset":
        confirm = input("Are you sure you want to reset the database? (y/N): ")
        if confirm.lower() == 'y':
            reset_database()
        else:
            print("Database reset cancelled")
    elif command == "reload":
        print("🔄 Reloading AWS data...")
        os.system("python3 load_aws_data.py")
    else:
        print(f"Unknown command: {command}")

if __name__ == "__main__":
    main() 