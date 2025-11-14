// User and Authentication Types
export interface User {
  id: string;
  email: string;
  first_name: string;
  last_name: string;
  created_at: string;
}

export interface LoginRequest {
  email: string;
  password: string;
}

export interface RegisterRequest {
  email: string;
  password: string;
  first_name: string;
  last_name: string;
}

export interface AuthResponse {
  access_token: string;
  user: User;
}

// Log File Types
export interface LogFile {
  id: string;
  filename: string;
  file_size: number;
  file_hash: string;
  log_type: string;
  upload_status: 'pending' | 'processing' | 'completed' | 'failed';
  parsed_entries: number;
  uploaded_at: string;
  created_at: string;
  processed_at: string | null;
  error_message: string | null;
}

// Log Entry Types
export interface LogEntry {
  id: string;
  log_file_id: string;
  timestamp: string;
  source_ip: string;
  destination_ip: string;
  username: string;
  url: string;
  hostname: string;
  url_category: string;
  threat_name: string | null;
  malware_type: string | null;
  risk_score: number;
  action: string;
  policy: string;
  bytes_sent: number;
  bytes_received: number;
  http_status_code: number | null;
  user_agent: string | null;
  device_hostname: string | null;
  bypassed_traffic: boolean;
}

// Anomaly Types
export interface Anomaly {
  id: string;
  log_file_id: string;
  anomaly_type: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  title: string;
  description: string;
  confidence_score: number;
  detection_method: string;
  ai_model_used: string;
  affected_user: string | null;
  affected_ip: string | null;
  affected_url: string | null;
  recommendation: string;
  detected_at: string;
  related_log_entries: string[];
}

// Analysis Types
export interface Statistics {
  total_entries: number;
  threat_count: number;
  high_risk_count: number;
  bypassed_count: number;
  unique_users: number;
  unique_ips: number;
  unique_source_ips: number;
  unique_dest_ips: number;
  blocked_count: number;
  allowed_count: number;
  total_bytes: number;
  total_bytes_sent: number;
  total_bytes_received: number;
  top_categories: Array<{
    category: string;
    count: number;
  }>;
  top_users: Array<{
    username: string;
    count: number;
  }>;
  top_threats?: Array<{
    threat_name: string;
    count: number;
  }>;
  action_breakdown: Array<{
    action: string;
    count: number;
  }>;
}

export interface AnomalyStatistics {
  total: number;
  by_severity: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  by_type: Record<string, number>;
}

export interface TimelineEvent {
  timestamp: string;
  event_type: string;
  severity: string;
  description: string;
  user: string | null;
  ip: string | null;
}

export interface AnalysisResponse {
  log_file: LogFile;
  statistics: Statistics;
  anomaly_statistics: AnomalyStatistics;
  timeline: TimelineEvent[];
  critical_anomalies: Anomaly[];
}

// API Response Types
export interface ApiError {
  error: string;
  message?: string;
}

export interface UploadResponse {
  message: string;
  log_file: LogFile;
}

export interface AnomaliesResponse {
  anomalies: Anomaly[];
  total: number;
  page: number;
  per_page: number;
}

