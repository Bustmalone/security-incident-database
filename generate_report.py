#!/usr/bin/env python3
"""
Generate Security Incident Report
Creates a formatted report from SQL query results
"""

import sys
import argparse
import cx_Oracle
from datetime import datetime


def generate_incident_report(incident_id, db_config):
    """Generate a detailed incident report"""
    try:
        # Connect to database
        connection = cx_Oracle.connect(
            db_config['username'],
            db_config['password'],
            db_config['dsn']
        )
        cursor = connection.cursor()
        
        # Query incident details
        query = """
        SELECT incident_id, incident_type, severity, description, 
               detected_time, resolved_time, status, assigned_to
        FROM security_incidents
        WHERE incident_id = :incident_id
        """
        cursor.execute(query, incident_id=incident_id)
        incident = cursor.fetchone()
        
        if not incident:
            print(f"Incident {incident_id} not found")
            return
        
        # Generate report
        report = f"""
{'='*60}
SECURITY INCIDENT REPORT
{'='*60}

Incident ID: {incident[0]}
Type: {incident[1]}
Severity: {incident[2]}
Status: {incident[6]}
Assigned To: {incident[7]}

Description:
{incident[3]}

Detected: {incident[4]}
Resolved: {incident[5] if incident[5] else 'Not yet resolved'}

{'='*60}
"""
        print(report)
        
        # Save to file
        filename = f"incident_report_{incident_id}_{datetime.now().strftime('%Y%m%d')}.txt"
        with open(filename, 'w') as f:
            f.write(report)
        
        print(f"Report saved to: {filename}")
        
        cursor.close()
        connection.close()
    
    except Exception as e:
        print(f"Error generating report: {e}")


def main():
    parser = argparse.ArgumentParser(description="Generate Security Incident Report")
    parser.add_argument("--incident-id", type=int, required=True, help="Incident ID")
    parser.add_argument("--username", help="Database username")
    parser.add_argument("--password", help="Database password")
    parser.add_argument("--dsn", help="Database DSN")
    
    args = parser.parse_args()
    
    # Database configuration
    db_config = {
        'username': args.username or 'your_username',
        'password': args.password or 'your_password',
        'dsn': args.dsn or 'localhost/XE'
    }
    
    generate_incident_report(args.incident_id, db_config)


if __name__ == "__main__":
    main()

