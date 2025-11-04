-- Login Analysis Queries
-- Advanced SQL queries for security incident investigation

-- Query 1: Failed Login Attempts in Last 24 Hours
SELECT 
    username,
    COUNT(*) as failed_attempts,
    MAX(login_time) as last_attempt,
    LISTAGG(DISTINCT ip_address, ', ') WITHIN GROUP (ORDER BY ip_address) as source_ips
FROM login_logs
WHERE status = 'FAILED'
  AND login_time > SYSDATE - 1
GROUP BY username
HAVING COUNT(*) > 5
ORDER BY failed_attempts DESC;

-- Query 2: Brute Force Attack Detection
SELECT 
    ip_address,
    COUNT(DISTINCT username) as unique_users_targeted,
    COUNT(*) as total_failed_attempts,
    MIN(login_time) as first_attempt,
    MAX(login_time) as last_attempt,
    ROUND((MAX(login_time) - MIN(login_time)) * 24 * 60, 2) as duration_minutes
FROM login_logs
WHERE status = 'FAILED'
  AND login_time > SYSDATE - 1
GROUP BY ip_address
HAVING COUNT(*) > 10
ORDER BY total_failed_attempts DESC;

-- Query 3: Suspicious Login Patterns
SELECT 
    username,
    COUNT(*) as total_attempts,
    SUM(CASE WHEN status = 'FAILED' THEN 1 ELSE 0 END) as failed_attempts,
    SUM(CASE WHEN status = 'SUCCESS' THEN 1 ELSE 0 END) as successful_attempts,
    COUNT(DISTINCT ip_address) as unique_ips,
    COUNT(DISTINCT TO_CHAR(login_time, 'YYYY-MM-DD')) as unique_days
FROM login_logs
WHERE login_time > SYSDATE - 7
GROUP BY username
HAVING COUNT(DISTINCT ip_address) > 3
   OR (SUM(CASE WHEN status = 'FAILED' THEN 1 ELSE 0 END) > 10)
ORDER BY total_attempts DESC;

-- Query 4: Successful Logins After Multiple Failures
WITH failed_logins AS (
    SELECT username, ip_address, COUNT(*) as failures
    FROM login_logs
    WHERE status = 'FAILED'
      AND login_time > SYSDATE - 1
    GROUP BY username, ip_address
    HAVING COUNT(*) > 5
)
SELECT 
    ll.username,
    ll.ip_address,
    f.failures,
    ll.login_time as successful_login_time
FROM login_logs ll
INNER JOIN failed_logins f ON ll.username = f.username AND ll.ip_address = f.ip_address
WHERE ll.status = 'SUCCESS'
  AND ll.login_time > (SELECT MAX(login_time) FROM login_logs 
                       WHERE username = ll.username 
                       AND ip_address = ll.ip_address 
                       AND status = 'FAILED')
ORDER BY ll.login_time DESC;

-- Query 5: Employee Login Activity Summary
SELECT 
    e.username,
    e.full_name,
    e.department,
    e.account_status,
    COUNT(ll.log_id) as total_logins,
    MAX(ll.login_time) as last_login,
    COUNT(DISTINCT ll.ip_address) as unique_ips,
    SUM(CASE WHEN ll.status = 'FAILED' THEN 1 ELSE 0 END) as failed_attempts
FROM employee_data e
LEFT JOIN login_logs ll ON e.username = ll.username
WHERE ll.login_time > SYSDATE - 30 OR ll.login_time IS NULL
GROUP BY e.username, e.full_name, e.department, e.account_status
ORDER BY total_logins DESC NULLS LAST;

