-- Sample Data for Security Incident Database
-- Insert sample data for testing queries

-- Insert sample employee data
INSERT INTO employee_data (employee_id, username, full_name, department, email, phone, access_level, account_status, last_login)
VALUES (employee_data_seq.NEXTVAL, 'jdoe', 'John Doe', 'IT', 'jdoe@company.com', '555-0101', 'ADMIN', 'ACTIVE', SYSDATE - 5);

INSERT INTO employee_data (employee_id, username, full_name, department, email, phone, access_level, account_status, last_login)
VALUES (employee_data_seq.NEXTVAL, 'asmith', 'Alice Smith', 'HR', 'asmith@company.com', '555-0102', 'USER', 'ACTIVE', SYSDATE - 2);

INSERT INTO employee_data (employee_id, username, full_name, department, email, phone, access_level, account_status, last_login)
VALUES (employee_data_seq.NEXTVAL, 'bjones', 'Bob Jones', 'Finance', 'bjones@company.com', '555-0103', 'USER', 'ACTIVE', SYSDATE - 1);

-- Insert sample login logs
INSERT INTO login_logs (log_id, username, ip_address, login_time, status, failure_reason, user_agent)
VALUES (login_logs_seq.NEXTVAL, 'jdoe', '192.168.1.100', SYSDATE - 1/24, 'SUCCESS', NULL, 'Mozilla/5.0');

INSERT INTO login_logs (log_id, username, ip_address, login_time, status, failure_reason, user_agent)
VALUES (login_logs_seq.NEXTVAL, 'asmith', '10.0.0.50', SYSDATE - 2/24, 'SUCCESS', NULL, 'Chrome/120.0');

-- Insert failed login attempts (brute force simulation)
INSERT INTO login_logs (log_id, username, ip_address, login_time, status, failure_reason, user_agent)
SELECT 
    login_logs_seq.NEXTVAL,
    'admin',
    '203.0.113.10',
    SYSDATE - (ROWNUM / 1440),
    'FAILED',
    'Invalid password',
    'Python/3.9'
FROM dual
CONNECT BY ROWNUM <= 15;

-- Insert security incidents
INSERT INTO security_incidents (incident_id, incident_type, severity, description, detected_time, status, assigned_to)
VALUES (security_incidents_seq.NEXTVAL, 'BRUTE_FORCE', 'HIGH', 
        'Multiple failed login attempts detected from IP 203.0.113.10', 
        SYSDATE - 1/24, 'INVESTIGATING', 'security_team');

COMMIT;

