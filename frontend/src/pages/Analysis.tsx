import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { analysisApi, visualizationApi } from '../services/api';
import {
  ArrowLeft,
  AlertTriangle,
  Shield,
  Activity,
  Users,
  FileText,
  AlertCircle,
  RefreshCw,
} from 'lucide-react';
import { BarChart, Bar, PieChart, Pie, Cell, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import type { AnalysisResponse } from '../types';
import MetricsOverview from '../components/MetricsOverview';
import {
  RiskTrendlineWidget,
  EventTimelineWidget,
  AnomalyTimeSeriesWidget,
  RequestsPerMinuteWidget,
} from '../components/VisualizationWidgets';

const COLORS = {
  critical: '#dc2626',
  high: '#f59e0b',
  medium: '#fbbf24',
  low: '#22c55e',
};

const Analysis: React.FC = () => {
  const { logFileId } = useParams<{ logFileId: string }>();
  const navigate = useNavigate();
  const [analysis, setAnalysis] = useState<AnalysisResponse | null>(null);
  const [visualizations, setVisualizations] = useState<any>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [isLoadingViz, setIsLoadingViz] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    if (logFileId) {
      loadAnalysis();
      loadVisualizations();
    }
  }, [logFileId]);

  const loadAnalysis = async () => {
    if (!logFileId) {
      setError('No log file ID provided');
      setIsLoading(false);
      return;
    }

    try {
      const data = await analysisApi.getAnalysis(logFileId);
      if (data) {
        setAnalysis(data);
      } else {
        setError('No analysis data received');
      }
    } catch (err: any) {
      console.error('Failed to load analysis:', err);
      setError(err.response?.data?.error || err.message || 'Failed to load analysis');
    } finally {
      setIsLoading(false);
    }
  };

  const loadVisualizations = async () => {
    if (!logFileId) {
      setIsLoadingViz(false);
      return;
    }

    try {
      const data = await visualizationApi.getAllVisualizations(logFileId);
      if (data) {
        console.log('📊 Visualization data received:', data);
        setVisualizations(data);
      }
    } catch (err: any) {
      console.error('Failed to load visualizations:', err);
      // Don't set error state for visualizations, just log it
    } finally {
      setIsLoadingViz(false);
    }
  };

  if (isLoading) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 flex items-center justify-center">
        <div className="text-center">
          <div className="inline-block animate-spin rounded-full h-12 w-12 border-b-2 border-primary-500 mb-4"></div>
          <p className="text-gray-400">Loading analysis...</p>
        </div>
      </div>
    );
  }

  if (error || !analysis) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 flex items-center justify-center">
        <div className="card max-w-md">
          <AlertCircle className="h-12 w-12 text-danger-400 mx-auto mb-4" />
          <h2 className="text-xl font-bold text-white text-center mb-2">Error Loading Analysis</h2>
          <p className="text-gray-400 text-center mb-6">{error}</p>
          <button onClick={() => navigate('/dashboard')} className="btn-primary w-full">
            Back to Dashboard
          </button>
        </div>
      </div>
    );
  }

  const { statistics, anomaly_statistics } = analysis;

  // Prepare chart data
  const severityData = [
    { name: 'Critical', value: anomaly_statistics.by_severity.critical, color: COLORS.critical },
    { name: 'High', value: anomaly_statistics.by_severity.high, color: COLORS.high },
    { name: 'Medium', value: anomaly_statistics.by_severity.medium, color: COLORS.medium },
    { name: 'Low', value: anomaly_statistics.by_severity.low, color: COLORS.low },
  ];

  const categoryData = statistics.top_categories.slice(0, 10).map(cat => ({
    name: cat.category.length > 20 ? cat.category.substring(0, 20) + '...' : cat.category,
    count: cat.count,
  }));

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900">
      {/* Header */}
      <header className="bg-slate-800 border-b border-slate-700 shadow-lg">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-4">
              <button
                onClick={() => navigate('/dashboard')}
                className="p-2 hover:bg-slate-700 rounded-lg transition-colors"
              >
                <ArrowLeft className="h-6 w-6 text-gray-400" />
              </button>
              <div>
                <h1 className="text-2xl font-bold text-white">Log Analysis</h1>
                <p className="text-sm text-gray-400">{analysis.log_file.filename}</p>
              </div>
            </div>
            <div className="flex items-center space-x-2">
              <FileText className="h-5 w-5 text-primary-400" />
              <span className="text-gray-300">{statistics.total_entries} entries</span>
            </div>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Metrics Overview - At a Glance */}
        <div className="mb-8">
          <MetricsOverview
            statistics={statistics}
            anomalyStatistics={anomaly_statistics}
            logFile={analysis.log_file}
          />
        </div>

        {/* Divider */}
        <div className="border-t border-slate-700 my-8"></div>

        {/* Stats Overview */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
          <div className="card">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-gray-400 mb-1">Total Anomalies</p>
                <p className="text-3xl font-bold text-white">{anomaly_statistics.total}</p>
              </div>
              <AlertTriangle className="h-12 w-12 text-warning-400" />
            </div>
          </div>

          <div className="card">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-gray-400 mb-1">Critical Threats</p>
                <p className="text-3xl font-bold text-danger-400">{statistics.threat_count}</p>
              </div>
              <Shield className="h-12 w-12 text-danger-400" />
            </div>
          </div>

          <div className="card">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-gray-400 mb-1">Unique Users</p>
                <p className="text-3xl font-bold text-white">{statistics.unique_users}</p>
              </div>
              <Users className="h-12 w-12 text-primary-400" />
            </div>
          </div>

          <div className="card">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-gray-400 mb-1">High Risk Events</p>
                <p className="text-3xl font-bold text-warning-400">{statistics.high_risk_count}</p>
              </div>
              <Activity className="h-12 w-12 text-warning-400" />
            </div>
          </div>
        </div>

        {/* Charts Row */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
          {/* Severity Distribution */}
          <div className="card">
            <h3 className="text-lg font-bold text-white mb-4">Anomaly Severity Distribution</h3>
            <ResponsiveContainer width="100%" height={300}>
              <PieChart>
                <Pie
                  data={severityData}
                  cx="50%"
                  cy="50%"
                  labelLine={false}
                  label={({ name, value }) => `${name}: ${value}`}
                  outerRadius={100}
                  fill="#8884d8"
                  dataKey="value"
                >
                  {severityData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#1e293b',
                    border: '1px solid #475569',
                    borderRadius: '0.5rem',
                  }}
                />
              </PieChart>
            </ResponsiveContainer>
          </div>

          {/* Top Categories */}
          <div className="card">
            <h3 className="text-lg font-bold text-white mb-4">Top URL Categories</h3>
            <ResponsiveContainer width="100%" height={300}>
              <BarChart data={categoryData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#475569" />
                <XAxis dataKey="name" stroke="#94a3b8" angle={-45} textAnchor="end" height={100} />
                <YAxis stroke="#94a3b8" />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#1e293b',
                    border: '1px solid #475569',
                    borderRadius: '0.5rem',
                  }}
                />
                <Bar dataKey="count" fill="#0ea5e9" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Divider */}
        <div className="border-t border-slate-700 my-8"></div>

        {/* Advanced Visualizations Section */}
        <div className="mb-6 flex items-center justify-between">
          <div>
            <h2 className="text-2xl font-bold text-white">Advanced Analytics</h2>
            <p className="text-sm text-gray-400 mt-1">
              Statistical analysis and time-series visualizations
            </p>
          </div>
          <button
            onClick={loadVisualizations}
            disabled={isLoadingViz}
            className="flex items-center space-x-2 px-4 py-2 bg-slate-700 hover:bg-slate-600 text-white rounded-lg transition-colors disabled:opacity-50"
          >
            <RefreshCw className={`h-4 w-4 ${isLoadingViz ? 'animate-spin' : ''}`} />
            <span>Refresh</span>
          </button>
        </div>

        {isLoadingViz ? (
          <div className="card">
            <div className="text-center py-12">
              <div className="inline-block animate-spin rounded-full h-8 w-8 border-b-2 border-primary-500 mb-4"></div>
              <p className="text-gray-400">Loading visualizations...</p>
            </div>
          </div>
        ) : visualizations ? (
          <>
            {/* Time Series Visualizations */}
            <div className="grid grid-cols-1 gap-6 mb-8">
              {/* Anomaly Time Series */}
              {visualizations.anomaly_time_series && (
                <AnomalyTimeSeriesWidget data={visualizations.anomaly_time_series} />
              )}

              {/* Risk Score Trendline */}
              {visualizations.risk_trendline && (
                <RiskTrendlineWidget data={visualizations.risk_trendline} />
              )}

              {/* Event Timeline */}
              {visualizations.event_timeline && (
                <EventTimelineWidget data={visualizations.event_timeline} />
              )}

              {/* Requests Per Minute */}
              {visualizations.event_timeline && visualizations.event_timeline.request_counts && (
                <RequestsPerMinuteWidget
                  data={{
                    timestamps: visualizations.event_timeline.time_buckets,
                    request_counts: visualizations.event_timeline.request_counts,
                  }}
                />
              )}
            </div>

            {/* Statistical Summary */}
            {visualizations.statistical_summary && (
              <div className="card mb-8">
                <h3 className="text-lg font-bold text-white mb-4">Statistical Summary</h3>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                  <div className="bg-slate-700/50 p-4 rounded-lg">
                    <p className="text-sm text-gray-400 mb-1">Total Anomalies</p>
                    <p className="text-2xl font-bold text-white">
                      {visualizations.statistical_summary.total_anomalies}
                    </p>
                  </div>
                  <div className="bg-slate-700/50 p-4 rounded-lg">
                    <p className="text-sm text-gray-400 mb-1">Avg Risk Score</p>
                    <p className="text-2xl font-bold text-white">
                      {visualizations.statistical_summary.avg_risk_score?.toFixed(1)}
                    </p>
                  </div>
                  <div className="bg-slate-700/50 p-4 rounded-lg">
                    <p className="text-sm text-gray-400 mb-1">Max Risk Score</p>
                    <p className="text-2xl font-bold text-danger-400">
                      {visualizations.statistical_summary.max_risk_score}
                    </p>
                  </div>
                  <div className="bg-slate-700/50 p-4 rounded-lg">
                    <p className="text-sm text-gray-400 mb-1">Unique Users</p>
                    <p className="text-2xl font-bold text-white">
                      {visualizations.statistical_summary.unique_users}
                    </p>
                  </div>
                </div>
              </div>
            )}
          </>
        ) : (
          <div className="card">
            <div className="text-center py-8 text-gray-400">
              Failed to load visualizations. Click refresh to try again.
            </div>
          </div>
        )}

        {/* Note: Critical Anomalies and All Anomalies are now accessible via clickable metric cards above */}
      </main>
    </div>
  );
};

export default Analysis;

