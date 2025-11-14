-- CyberDucky Mini SIEM - PostgreSQL Database Schema
-- This schema follows normalization principles and includes proper indexing for performance

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Enable pgcrypto for password hashing (if needed)
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ============================================================================
-- USERS TABLE
-- ============================================================================
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    first_name VARCHAR(100),
    last_name VARCHAR(100),
    is_active BOOLEAN DEFAULT TRUE,
    is_admin BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP WITH TIME ZONE
);

-- Index for faster email lookups
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_active ON users(is_active);

-- ============================================================================
-- LOG FILES TABLE
-- ============================================================================
CREATE TYPE log_file_status AS ENUM ('pending', 'processing', 'completed', 'failed');
CREATE TYPE log_type AS ENUM ('zscaler', 'apache', 'nginx', 'windows', 'linux', 'custom');

CREATE TABLE log_files (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    filename VARCHAR(255) NOT NULL,
    original_filename VARCHAR(255) NOT NULL,
    file_path TEXT NOT NULL,
    file_size BIGINT NOT NULL, -- in bytes
    file_hash VARCHAR(64), -- SHA-256 hash for deduplication
    log_type log_type NOT NULL,
    status log_file_status DEFAULT 'pending',
    total_entries INTEGER DEFAULT 0,
    processed_entries INTEGER DEFAULT 0,
    error_message TEXT,
    uploaded_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    processing_started_at TIMESTAMP WITH TIME ZONE,
    processing_completed_at TIMESTAMP WITH TIME ZONE,
    metadata JSONB -- Additional metadata about the file
);

-- Indexes for performance
CREATE INDEX idx_log_files_user_id ON log_files(user_id);
CREATE INDEX idx_log_files_status ON log_files(status);
CREATE INDEX idx_log_files_uploaded_at ON log_files(uploaded_at DESC);
CREATE INDEX idx_log_files_log_type ON log_files(log_type);
CREATE INDEX idx_log_files_hash ON log_files(file_hash);

-- ============================================================================
-- LOG ENTRIES TABLE
-- ============================================================================
CREATE TYPE log_action AS ENUM ('allowed', 'blocked', 'denied', 'unknown');
CREATE TYPE protocol_type AS ENUM ('HTTP', 'HTTPS', 'FTP', 'SSH', 'DNS', 'SMTP', 'OTHER');

CREATE TABLE log_entries (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    log_file_id UUID NOT NULL REFERENCES log_files(id) ON DELETE CASCADE,
    
    -- Temporal information
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
    
    -- Network information
    source_ip INET,
    source_port INTEGER,
    destination_ip INET,
    destination_port INTEGER,
    protocol protocol_type,
    
    -- HTTP/Web specific
    url TEXT,
    domain VARCHAR(255),
    http_method VARCHAR(10),
    http_status_code INTEGER,
    user_agent TEXT,
    referer TEXT,
    
    -- Action and categorization
    action log_action,
    category VARCHAR(100), -- e.g., "malware", "phishing", "social_media"
    threat_name VARCHAR(255),
    
    -- Data transfer
    bytes_sent BIGINT,
    bytes_received BIGINT,
    
    -- User information
    username VARCHAR(255),
    
    -- Raw and parsed data
    raw_log TEXT NOT NULL,
    parsed_data JSONB, -- Flexible storage for log-specific fields
    
    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for common queries
CREATE INDEX idx_log_entries_log_file_id ON log_entries(log_file_id);
CREATE INDEX idx_log_entries_timestamp ON log_entries(timestamp DESC);
CREATE INDEX idx_log_entries_source_ip ON log_entries(source_ip);
CREATE INDEX idx_log_entries_destination_ip ON log_entries(destination_ip);
CREATE INDEX idx_log_entries_action ON log_entries(action);
CREATE INDEX idx_log_entries_domain ON log_entries(domain);
CREATE INDEX idx_log_entries_category ON log_entries(category);

-- GIN index for JSONB queries
CREATE INDEX idx_log_entries_parsed_data ON log_entries USING GIN (parsed_data);

-- Composite index for timeline queries
CREATE INDEX idx_log_entries_file_timestamp ON log_entries(log_file_id, timestamp DESC);

-- ============================================================================
-- ANOMALIES TABLE
-- ============================================================================
CREATE TYPE anomaly_type AS ENUM (
    'rate_limit_exceeded',
    'geo_anomaly',
    'unusual_user_agent',
    'port_scan',
    'data_exfiltration',
    'brute_force',
    'suspicious_pattern',
    'time_anomaly',
    'protocol_anomaly',
    'other'
);

CREATE TYPE severity_level AS ENUM ('low', 'medium', 'high', 'critical');

CREATE TABLE anomalies (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    log_entry_id UUID NOT NULL REFERENCES log_entries(id) ON DELETE CASCADE,
    log_file_id UUID NOT NULL REFERENCES log_files(id) ON DELETE CASCADE,
    
    -- Anomaly classification
    anomaly_type anomaly_type NOT NULL,
    severity severity_level NOT NULL,
    
    -- Scoring
    confidence_score DECIMAL(3, 2) NOT NULL CHECK (confidence_score >= 0 AND confidence_score <= 1),
    risk_score INTEGER CHECK (risk_score >= 0 AND risk_score <= 100),
    
    -- Description
    title VARCHAR(255) NOT NULL,
    description TEXT NOT NULL,
    recommendation TEXT, -- What SOC analyst should do
    
    -- AI/LLM generated content
    ai_explanation TEXT, -- LLM-generated explanation
    ai_model_used VARCHAR(50), -- e.g., "gpt-4", "claude-3", "statistical"
    
    -- Status tracking
    is_false_positive BOOLEAN DEFAULT FALSE,
    is_acknowledged BOOLEAN DEFAULT FALSE,
    acknowledged_by UUID REFERENCES users(id),
    acknowledged_at TIMESTAMP WITH TIME ZONE,
    
    -- Additional context
    metadata JSONB, -- Additional context (e.g., related IPs, patterns)
    
    -- Timestamps
    detected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Indexes
CREATE INDEX idx_anomalies_log_entry_id ON anomalies(log_entry_id);
CREATE INDEX idx_anomalies_log_file_id ON anomalies(log_file_id);
CREATE INDEX idx_anomalies_type ON anomalies(anomaly_type);
CREATE INDEX idx_anomalies_severity ON anomalies(severity);
CREATE INDEX idx_anomalies_confidence ON anomalies(confidence_score DESC);
CREATE INDEX idx_anomalies_detected_at ON anomalies(detected_at DESC);
CREATE INDEX idx_anomalies_false_positive ON anomalies(is_false_positive);

-- GIN index for metadata
CREATE INDEX idx_anomalies_metadata ON anomalies USING GIN (metadata);

-- ============================================================================
-- ANALYSIS SESSIONS TABLE (Optional - for tracking analysis runs)
-- ============================================================================
CREATE TABLE analysis_sessions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    log_file_id UUID NOT NULL REFERENCES log_files(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    
    -- Analysis configuration
    analysis_type VARCHAR(50), -- e.g., "full", "quick", "custom"
    parameters JSONB, -- Analysis parameters
    
    -- Results summary
    total_anomalies_found INTEGER DEFAULT 0,
    high_severity_count INTEGER DEFAULT 0,
    medium_severity_count INTEGER DEFAULT 0,
    low_severity_count INTEGER DEFAULT 0,
    
    -- Timing
    started_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP WITH TIME ZONE,
    duration_seconds INTEGER,
    
    -- Status
    status VARCHAR(20) DEFAULT 'running', -- running, completed, failed
    error_message TEXT
);

CREATE INDEX idx_analysis_sessions_log_file_id ON analysis_sessions(log_file_id);
CREATE INDEX idx_analysis_sessions_user_id ON analysis_sessions(user_id);

-- ============================================================================
-- AUDIT LOG TABLE (Optional - for compliance and debugging)
-- ============================================================================
CREATE TABLE audit_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    action VARCHAR(100) NOT NULL, -- e.g., "login", "upload_file", "delete_file"
    resource_type VARCHAR(50), -- e.g., "log_file", "anomaly"
    resource_id UUID,
    ip_address INET,
    user_agent TEXT,
    details JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX idx_audit_logs_action ON audit_logs(action);
CREATE INDEX idx_audit_logs_created_at ON audit_logs(created_at DESC);

-- ============================================================================
-- TRIGGERS
-- ============================================================================

-- Update updated_at timestamp automatically
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_anomalies_updated_at BEFORE UPDATE ON anomalies
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- VIEWS FOR COMMON QUERIES
-- ============================================================================

-- View for anomaly summary by file
CREATE VIEW anomaly_summary_by_file AS
SELECT 
    lf.id as log_file_id,
    lf.filename,
    lf.user_id,
    COUNT(a.id) as total_anomalies,
    COUNT(CASE WHEN a.severity = 'critical' THEN 1 END) as critical_count,
    COUNT(CASE WHEN a.severity = 'high' THEN 1 END) as high_count,
    COUNT(CASE WHEN a.severity = 'medium' THEN 1 END) as medium_count,
    COUNT(CASE WHEN a.severity = 'low' THEN 1 END) as low_count,
    AVG(a.confidence_score) as avg_confidence,
    MAX(a.detected_at) as last_anomaly_detected
FROM log_files lf
LEFT JOIN anomalies a ON lf.id = a.log_file_id
WHERE a.is_false_positive = FALSE
GROUP BY lf.id, lf.filename, lf.user_id;

-- View for top source IPs by anomaly count
CREATE VIEW top_anomalous_ips AS
SELECT 
    le.source_ip,
    COUNT(DISTINCT a.id) as anomaly_count,
    COUNT(DISTINCT le.log_file_id) as file_count,
    MAX(a.severity) as max_severity,
    AVG(a.confidence_score) as avg_confidence
FROM log_entries le
JOIN anomalies a ON le.id = a.log_entry_id
WHERE a.is_false_positive = FALSE
GROUP BY le.source_ip
ORDER BY anomaly_count DESC;

-- ============================================================================
-- SAMPLE DATA (for development/testing)
-- ============================================================================

-- Insert a test user (password: "password123" - hashed with bcrypt)
-- Note: In production, use proper password hashing in application code
INSERT INTO users (email, password_hash, first_name, last_name, is_admin)
VALUES (
    'admin@cyberducky.local',
    '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewY5GyYqNqNqNqNq', -- placeholder
    'Admin',
    'User',
    TRUE
);

-- ============================================================================
-- USEFUL QUERIES FOR DEVELOPMENT
-- ============================================================================

-- Get all anomalies for a specific file with log entry details
/*
SELECT 
    a.id,
    a.anomaly_type,
    a.severity,
    a.confidence_score,
    a.description,
    le.timestamp,
    le.source_ip,
    le.destination_ip,
    le.url
FROM anomalies a
JOIN log_entries le ON a.log_entry_id = le.id
WHERE a.log_file_id = 'YOUR_FILE_ID'
ORDER BY a.severity DESC, a.confidence_score DESC;
*/

-- Get timeline of events for a file
/*
SELECT 
    le.timestamp,
    le.source_ip,
    le.action,
    le.url,
    CASE WHEN a.id IS NOT NULL THEN TRUE ELSE FALSE END as is_anomalous,
    a.severity,
    a.anomaly_type
FROM log_entries le
LEFT JOIN anomalies a ON le.id = a.log_entry_id
WHERE le.log_file_id = 'YOUR_FILE_ID'
ORDER BY le.timestamp ASC;
*/

-- Get statistics for a file
/*
SELECT 
    COUNT(*) as total_entries,
    COUNT(DISTINCT source_ip) as unique_source_ips,
    COUNT(DISTINCT destination_ip) as unique_dest_ips,
    COUNT(CASE WHEN action = 'blocked' THEN 1 END) as blocked_count,
    COUNT(CASE WHEN action = 'allowed' THEN 1 END) as allowed_count,
    SUM(bytes_sent + bytes_received) as total_bytes
FROM log_entries
WHERE log_file_id = 'YOUR_FILE_ID';
*/

