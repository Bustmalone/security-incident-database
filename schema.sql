-- Security Incident Investigation Database Schema
-- Oracle Database Schema for Security Incident Tracking

-- Login Logs Table
CREATE TABLE login_logs (
    log_id NUMBER PRIMARY KEY,
    username VARCHAR2(50) NOT NULL,
    ip_address VARCHAR2(45) NOT NULL,
    login_time TIMESTAMP NOT NULL,
    status VARCHAR2(10) CHECK (status IN ('SUCCESS', 'FAILED')),
    failure_reason VARCHAR2(100),
    user_agent VARCHAR2(200),
    session_id VARCHAR2(100)
);

CREATE SEQUENCE login_logs_seq START WITH 1 INCREMENT BY 1;

CREATE INDEX idx_login_time ON login_logs(login_time);
CREATE INDEX idx_username ON login_logs(username);
CREATE INDEX idx_ip_address ON login_logs(ip_address);
CREATE INDEX idx_status ON login_logs(status);

-- Security Incidents Table
CREATE TABLE security_incidents (
    incident_id NUMBER PRIMARY KEY,
    incident_type VARCHAR2(50) NOT NULL,
    severity VARCHAR2(20) CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    description CLOB,
    detected_time TIMESTAMP NOT NULL,
    resolved_time TIMESTAMP,
    status VARCHAR2(20) CHECK (status IN ('OPEN', 'INVESTIGATING', 'RESOLVED', 'FALSE_POSITIVE')),
    assigned_to VARCHAR2(50)
);

CREATE SEQUENCE security_incidents_seq START WITH 1 INCREMENT BY 1;

CREATE INDEX idx_incident_time ON security_incidents(detected_time);
CREATE INDEX idx_incident_status ON security_incidents(status);

-- Employee Data Table (for incident correlation)
CREATE TABLE employee_data (
    employee_id NUMBER PRIMARY KEY,
    username VARCHAR2(50) UNIQUE NOT NULL,
    full_name VARCHAR2(100),
    department VARCHAR2(50),
    email VARCHAR2(100),
    phone VARCHAR2(20),
    access_level VARCHAR2(20),
    last_login TIMESTAMP,
    account_status VARCHAR2(20) CHECK (account_status IN ('ACTIVE', 'INACTIVE', 'LOCKED', 'SUSPENDED'))
);

CREATE SEQUENCE employee_data_seq START WITH 1 INCREMENT BY 1;

CREATE INDEX idx_employee_username ON employee_data(username);
CREATE INDEX idx_employee_dept ON employee_data(department);

-- Network Events Table
CREATE TABLE network_events (
    event_id NUMBER PRIMARY KEY,
    source_ip VARCHAR2(45) NOT NULL,
    destination_ip VARCHAR2(45) NOT NULL,
    destination_port NUMBER,
    protocol VARCHAR2(10),
    event_time TIMESTAMP NOT NULL,
    event_type VARCHAR2(50),
    bytes_sent NUMBER,
    bytes_received NUMBER,
    status VARCHAR2(20)
);

CREATE SEQUENCE network_events_seq START WITH 1 INCREMENT BY 1;

CREATE INDEX idx_network_time ON network_events(event_time);
CREATE INDEX idx_network_source ON network_events(source_ip);
CREATE INDEX idx_network_dest ON network_events(destination_ip);

-- Comments and Notes
COMMENT ON TABLE login_logs IS 'Stores authentication attempts and login events';
COMMENT ON TABLE security_incidents IS 'Tracks security incidents and investigations';
COMMENT ON TABLE employee_data IS 'Employee information for incident correlation';
COMMENT ON TABLE network_events IS 'Network traffic and connection events';

