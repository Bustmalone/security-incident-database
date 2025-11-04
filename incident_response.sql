-- Incident Response Queries
-- Queries for retrieving targeted employee data and incident correlation

-- Query 1: Get Employee Data for Incident Investigation
SELECT 
    e.employee_id,
    e.username,
    e.full_name,
    e.department,
    e.email,
    e.phone,
    e.access_level,
    e.account_status,
    e.last_login,
    (SELECT COUNT(*) FROM login_logs ll WHERE ll.username = e.username 
     AND ll.status = 'FAILED' AND ll.login_time > SYSDATE - 7) as recent_failed_logins
FROM employee_data e
WHERE e.username = :username
   OR e.email = :email
   OR e.employee_id = :employee_id;

-- Query 2: Login History for Specific Employee
SELECT 
    ll.login_time,
    ll.ip_address,
    ll.status,
    ll.failure_reason,
    ll.user_agent,
    CASE 
        WHEN ll.status = 'SUCCESS' THEN 'NORMAL'
        WHEN ll.status = 'FAILED' AND ll.login_time > SYSDATE - 1 THEN 'RECENT_FAILURE'
        ELSE 'HISTORICAL'
    END as login_category
FROM login_logs ll
WHERE ll.username = :username
  AND ll.login_time > SYSDATE - 30
ORDER BY ll.login_time DESC;

-- Query 3: Correlate Login Events with Network Events
SELECT 
    ll.username,
    ll.ip_address as login_ip,
    ll.login_time,
    ll.status,
    ne.destination_ip,
    ne.destination_port,
    ne.event_time,
    ne.event_type,
    ROUND((ne.event_time - ll.login_time) * 24 * 60, 2) as minutes_after_login
FROM login_logs ll
LEFT JOIN network_events ne ON ll.ip_address = ne.source_ip
WHERE ll.username = :username
  AND ll.login_time > SYSDATE - 1
  AND ne.event_time BETWEEN ll.login_time AND ll.login_time + 1/24  -- Within 1 hour
ORDER BY ll.login_time DESC, ne.event_time;

-- Query 4: Incident Summary Report
SELECT 
    si.incident_id,
    si.incident_type,
    si.severity,
    si.detected_time,
    si.status,
    si.assigned_to,
    COUNT(DISTINCT ll.username) as affected_users,
    COUNT(DISTINCT ll.ip_address) as source_ips,
    COUNT(*) as related_events
FROM security_incidents si
LEFT JOIN login_logs ll ON ll.login_time BETWEEN si.detected_time - 1/24 AND si.detected_time + 1/24
WHERE si.status != 'RESOLVED'
GROUP BY si.incident_id, si.incident_type, si.severity, si.detected_time, si.status, si.assigned_to
ORDER BY si.detected_time DESC;

-- Query 5: Retrieve All Data for Security Investigation
SELECT 
    'EMPLOYEE' as data_type,
    TO_CHAR(e.employee_id) as id,
    e.username,
    e.full_name,
    e.department,
    e.email,
    NULL as ip_address,
    e.last_login as timestamp
FROM employee_data e
WHERE e.username LIKE '%' || :search_term || '%'
   OR e.email LIKE '%' || :search_term || '%'
   OR e.full_name LIKE '%' || :search_term || '%'

UNION ALL

SELECT 
    'LOGIN_EVENT' as data_type,
    TO_CHAR(ll.log_id) as id,
    ll.username,
    NULL as full_name,
    NULL as department,
    NULL as email,
    ll.ip_address,
    ll.login_time as timestamp
FROM login_logs ll
WHERE ll.username LIKE '%' || :search_term || '%'
   OR ll.ip_address LIKE '%' || :search_term || '%'
   AND ll.login_time > SYSDATE - 30

ORDER BY timestamp DESC;

