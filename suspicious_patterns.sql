-- Suspicious Pattern Detection Queries
-- Advanced pattern matching for security incident investigation

-- Query 1: Multiple Failed Logins from Same IP
SELECT 
    ip_address,
    COUNT(DISTINCT username) as users_targeted,
    COUNT(*) as total_attempts,
    MIN(login_time) as first_attempt,
    MAX(login_time) as last_attempt
FROM login_logs
WHERE status = 'FAILED'
  AND login_time > SYSDATE - 1
GROUP BY ip_address
HAVING COUNT(DISTINCT username) > 5
ORDER BY users_targeted DESC, total_attempts DESC;

-- Query 2: Login Attempts Outside Business Hours
SELECT 
    username,
    ip_address,
    login_time,
    status,
    EXTRACT(HOUR FROM login_time) as login_hour
FROM login_logs
WHERE status = 'SUCCESS'
  AND login_time > SYSDATE - 7
  AND (EXTRACT(HOUR FROM login_time) < 8 OR EXTRACT(HOUR FROM login_time) > 18)
ORDER BY login_time DESC;

-- Query 3: Geographic Anomaly Detection (Multiple IPs)
SELECT 
    username,
    COUNT(DISTINCT ip_address) as unique_ips,
    LISTAGG(DISTINCT SUBSTR(ip_address, 1, INSTR(ip_address, '.', 1, 2) - 1), ', ') 
        WITHIN GROUP (ORDER BY ip_address) as ip_ranges,
    COUNT(*) as total_logins,
    MIN(login_time) as first_login,
    MAX(login_time) as last_login
FROM login_logs
WHERE status = 'SUCCESS'
  AND login_time > SYSDATE - 1
GROUP BY username
HAVING COUNT(DISTINCT ip_address) > 3
ORDER BY unique_ips DESC;

-- Query 4: Rapid Succession Login Attempts (Potential Account Takeover)
SELECT 
    username,
    ip_address,
    COUNT(*) as attempts_in_period,
    MIN(login_time) as first_attempt,
    MAX(login_time) as last_attempt,
    ROUND((MAX(login_time) - MIN(login_time)) * 24 * 60, 2) as duration_minutes
FROM login_logs
WHERE login_time > SYSDATE - 1
GROUP BY username, ip_address
HAVING COUNT(*) > 20 
   AND (MAX(login_time) - MIN(login_time)) < 1/24  -- Within 1 hour
ORDER BY attempts_in_period DESC;

-- Query 5: Pattern Matching for Known Attack Patterns
SELECT 
    username,
    ip_address,
    login_time,
    status,
    CASE 
        WHEN REGEXP_LIKE(username, '^(admin|administrator|root|test|guest)', 'i') THEN 'SUSPICIOUS_USERNAME'
        WHEN REGEXP_LIKE(ip_address, '^192\.168\.|^10\.|^172\.(1[6-9]|2[0-9]|3[01])\.') THEN 'INTERNAL_IP'
        ELSE 'EXTERNAL_IP'
    END as ip_category
FROM login_logs
WHERE status = 'FAILED'
  AND login_time > SYSDATE - 1
  AND (REGEXP_LIKE(username, '^(admin|administrator|root|test|guest)', 'i')
       OR REGEXP_LIKE(ip_address, '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'))
ORDER BY login_time DESC;

