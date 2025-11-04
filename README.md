# Security Incident Investigation Database

A SQL-based security incident analysis system for investigating security events. Analyzes login attempts, detects suspicious patterns, and retrieves targeted employee data. Uses advanced SQL queries with pattern matching, date filtering, and correlation analysis for efficient incident response.

## Features

- **Advanced SQL Queries** - Comprehensive queries for security incident analysis
- **Login Attempt Analysis** - Detect brute force and suspicious login patterns
- **Pattern Detection** - Identify anomalous behavior patterns
- **Automated Reporting** - Generate incident reports from query results

## Database Schema

The project includes SQL scripts for creating the necessary database schema for security incident tracking.

## Requirements

- Oracle Database 12c+ (or compatible SQL database)
- SQL*Plus or compatible SQL client
- Python 3.8+ (for reporting scripts)

## Installation

1. Create the database schema:
```bash
sqlplus username/password@database @schema.sql
```

2. Load sample data (optional):
```bash
sqlplus username/password@database @sample_data.sql
```

## Usage

### Analyze Login Attempts
```bash
sqlplus username/password@database @queries/login_analysis.sql
```

### Detect Suspicious Patterns
```bash
sqlplus username/password@database @queries/suspicious_patterns.sql
```

### Generate Incident Report
```bash
python generate_report.py --incident-id 12345
```

## Query Examples

### Find Failed Login Attempts
```sql
SELECT username, COUNT(*) as failed_attempts, 
       MAX(login_time) as last_attempt
FROM login_logs
WHERE status = 'FAILED'
  AND login_time > SYSDATE - 1
GROUP BY username
HAVING COUNT(*) > 5
ORDER BY failed_attempts DESC;
```

### Detect Brute Force Attacks
```sql
SELECT ip_address, COUNT(DISTINCT username) as unique_users,
       COUNT(*) as total_attempts
FROM login_logs
WHERE status = 'FAILED'
  AND login_time > SYSDATE - 1
GROUP BY ip_address
HAVING COUNT(*) > 10
ORDER BY total_attempts DESC;
```

## Project Structure

```
security-incident-database/
├── schema.sql              # Database schema creation
├── sample_data.sql         # Sample data for testing
├── queries/
│   ├── login_analysis.sql  # Login attempt queries
│   ├── suspicious_patterns.sql  # Pattern detection
│   └── incident_response.sql    # Incident response queries
├── reports/
│   └── generate_report.py  # Python reporting script
├── README.md              # This file
└── .gitignore
```

## Security Notice

⚠️ **This database may contain sensitive security information. Ensure proper access controls and encryption are in place.**

## License

MIT License

## Author

John Bustamante - Cybersecurity Professional

