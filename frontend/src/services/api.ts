import axios, { AxiosError } from 'axios';
import type {
  LoginRequest,
  RegisterRequest,
  AuthResponse,
  UploadResponse,
  AnalysisResponse,
  AnomaliesResponse,
  LogFile,
  ApiError,
} from '../types';

const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:5000/api';

// Create axios instance
const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Request interceptor to add auth token
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('access_token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => Promise.reject(error)
);

// Response interceptor to handle errors
api.interceptors.response.use(
  (response) => response,
  (error: AxiosError<ApiError>) => {
    if (error.response?.status === 401) {
      // Token expired or invalid
      localStorage.removeItem('access_token');
      localStorage.removeItem('user');
      window.location.href = '/login';
    }
    return Promise.reject(error);
  }
);

// Auth API
export const authApi = {
  register: async (data: RegisterRequest): Promise<AuthResponse> => {
    const response = await api.post<AuthResponse>('/auth/register', data);
    return response.data;
  },

  login: async (data: LoginRequest): Promise<AuthResponse> => {
    const response = await api.post<AuthResponse>('/auth/login', data);
    // Store token and user info
    localStorage.setItem('access_token', response.data.access_token);
    localStorage.setItem('user', JSON.stringify(response.data.user));
    return response.data;
  },

  logout: () => {
    localStorage.removeItem('access_token');
    localStorage.removeItem('user');
  },

  getCurrentUser: () => {
    const userStr = localStorage.getItem('user');
    return userStr ? JSON.parse(userStr) : null;
  },

  isAuthenticated: () => {
    return !!localStorage.getItem('access_token');
  },
};

// Upload API
export const uploadApi = {
  uploadLogFile: async (file: File, logType: string = 'zscaler'): Promise<UploadResponse> => {
    const formData = new FormData();
    formData.append('file', file);
    formData.append('log_type', logType);

    const response = await api.post<UploadResponse>('/upload', formData, {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
    });
    return response.data;
  },

  getLogFiles: async (): Promise<LogFile[]> => {
    const response = await api.get<{ log_files: LogFile[] }>('/upload');
    return response.data.log_files;
  },

  getLogFile: async (logFileId: string): Promise<LogFile> => {
    const response = await api.get<LogFile>(`/upload/${logFileId}`);
    return response.data;
  },

  reprocessLogFile: async (logFileId: string): Promise<{ message: string; log_file: LogFile }> => {
    const response = await api.post<{ message: string; log_file: LogFile }>(`/upload/${logFileId}/reprocess`);
    return response.data;
  },

  deleteLogFile: async (logFileId: string): Promise<{ message: string }> => {
    const response = await api.delete<{ message: string }>(`/upload/${logFileId}`);
    return response.data;
  },
};

// Analysis API
export const analysisApi = {
  getAnalysis: async (logFileId: string): Promise<AnalysisResponse> => {
    const response = await api.get<AnalysisResponse>(`/analysis/${logFileId}`);
    return response.data;
  },

  getStatistics: async (logFileId: string) => {
    const response = await api.get(`/analysis/${logFileId}/statistics`);
    return response.data;
  },

  getTimeline: async (logFileId: string) => {
    const response = await api.get(`/analysis/${logFileId}/timeline`);
    return response.data;
  },
};

// Anomaly API
export const anomalyApi = {
  getAnomalies: async (
    logFileId: string,
    page: number = 1,
    perPage: number = 10,
    severity?: string,
    search?: string
  ): Promise<AnomaliesResponse> => {
    const params = new URLSearchParams({
      page: page.toString(),
      per_page: perPage.toString(),
    });
    if (severity) {
      params.append('severity', severity);
    }
    if (search) {
      params.append('search', search);
    }

    const response = await api.get<AnomaliesResponse>(
      `/anomalies/${logFileId}?${params.toString()}`
    );
    return response.data;
  },

  getAnomaly: async (anomalyId: string) => {
    const response = await api.get(`/anomalies/detail/${anomalyId}`);
    return response.data;
  },

  getLogEntryForAnomaly: async (logEntryId: string) => {
    const response = await api.get(`/log-entries/${logEntryId}`);
    return response.data;
  },
};

// Log Entries API
export const logEntriesApi = {
  getEntries: async (
    logFileId: string,
    page: number = 1,
    perPage: number = 10,
    search?: string,
    filterType?: string
  ) => {
    const params = new URLSearchParams({
      page: page.toString(),
      per_page: perPage.toString(),
    });
    if (search) {
      params.append('search', search);
    }
    if (filterType) {
      params.append('filter_type', filterType);
    }

    const response = await api.get(
      `/analysis/${logFileId}/entries?${params.toString()}`
    );
    return response.data;
  },

  getUsers: async (
    logFileId: string,
    page: number = 1,
    perPage: number = 10,
    search?: string
  ) => {
    const params = new URLSearchParams({
      page: page.toString(),
      per_page: perPage.toString(),
    });
    if (search) {
      params.append('search', search);
    }

    const response = await api.get(
      `/analysis/${logFileId}/users?${params.toString()}`
    );
    return response.data;
  },

  getIPs: async (
    logFileId: string,
    page: number = 1,
    perPage: number = 10,
    search?: string,
    ipType: 'source' | 'destination' = 'source'
  ) => {
    const params = new URLSearchParams({
      page: page.toString(),
      per_page: perPage.toString(),
      ip_type: ipType,
    });
    if (search) {
      params.append('search', search);
    }

    const response = await api.get(
      `/analysis/${logFileId}/ips?${params.toString()}`
    );
    return response.data;
  },
};

// Visualization API
export const visualizationApi = {
  getAllVisualizations: async (logFileId: string) => {
    const response = await api.get(`/visualization/all-visualizations/${logFileId}`);
    return response.data;
  },

  getRiskTrendline: async (logFileId: string, user?: string) => {
    const params = user ? `?user=${user}` : '';
    const response = await api.get(`/visualization/risk-trendline/${logFileId}${params}`);
    return response.data;
  },

  getZScoreHeatmap: async (logFileId: string, metric: string = 'risk_score') => {
    const response = await api.get(`/visualization/z-score-heatmap/${logFileId}?metric=${metric}`);
    return response.data;
  },

  getAnomalyScatter: async (logFileId: string) => {
    const response = await api.get(`/visualization/anomaly-scatter/${logFileId}`);
    return response.data;
  },

  getBoxplot: async (logFileId: string, metric: string = 'risk_score') => {
    const response = await api.get(`/visualization/boxplot-per-user/${logFileId}?metric=${metric}`);
    return response.data;
  },

  getDensityPlot: async (logFileId: string, metric: string = 'risk_score') => {
    const response = await api.get(`/visualization/density-plot/${logFileId}?metric=${metric}`);
    return response.data;
  },

  getControlChart: async (logFileId: string, metric: string = 'risk_score', user?: string) => {
    const params = user ? `?metric=${metric}&user=${user}` : `?metric=${metric}`;
    const response = await api.get(`/visualization/ewma-control-chart/${logFileId}${params}`);
    return response.data;
  },

  getEventTimeline: async (logFileId: string, bucketSize: string = 'hour') => {
    const response = await api.get(`/visualization/event-timeline/${logFileId}?bucket_size=${bucketSize}`);
    return response.data;
  },

  getAnomalyTimeSeries: async (logFileId: string, bucketSize: string = 'hour') => {
    const response = await api.get(`/visualization/anomaly-time-series/${logFileId}?bucket_size=${bucketSize}`);
    return response.data;
  },

  getStatisticalSummary: async (logFileId: string) => {
    const response = await api.get(`/visualization/statistical-summary/${logFileId}`);
    return response.data;
  },

  getRequestsPerMinute: async (logFileId: string, groupBy: string = 'user') => {
    const response = await api.get(`/visualization/requests-per-minute/${logFileId}?group_by=${groupBy}`);
    return response.data;
  },
};

// Dashboard API
export const dashboardApi = {
  getOverview: async () => {
    const response = await api.get('/dashboard/overview');
    return response.data;
  },

  getAnomalyTrends: async () => {
    const response = await api.get('/dashboard/anomaly-trends');
    return response.data;
  },

  getTopThreats: async () => {
    const response = await api.get('/dashboard/top-threats');
    return response.data;
  },

  getAllFilesStats: async () => {
    const response = await api.get('/dashboard/all-files-stats');
    return response.data;
  },

  getUnifiedAnalysis: async (filters?: {
    username?: string;
    ip?: string;
    threat_name?: string;
    category?: string;
    min_risk?: number;
  }) => {
    const params = new URLSearchParams();
    if (filters?.username) params.append('username', filters.username);
    if (filters?.ip) params.append('ip', filters.ip);
    if (filters?.threat_name) params.append('threat_name', filters.threat_name);
    if (filters?.category) params.append('category', filters.category);
    if (filters?.min_risk !== undefined) params.append('min_risk', filters.min_risk.toString());

    const response = await api.get(`/dashboard/unified-analysis?${params.toString()}`);
    return response.data;
  },
};

export default api;

