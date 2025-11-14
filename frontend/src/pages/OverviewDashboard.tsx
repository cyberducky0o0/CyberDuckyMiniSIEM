import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { dashboardApi, visualizationApi } from '../services/api';
import NavigationBar from '../components/NavigationBar';
import {
  FileText,
  AlertTriangle,
  Shield,
  Activity,
  TrendingUp,
  Users,
  Globe,
  RefreshCw,
  Sparkles,
} from 'lucide-react';
import {
  BarChart,
  Bar,
  LineChart,
  Line,
  PieChart as RechartsPieChart,
  Pie,
  Cell,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
  AreaChart,
  Area,
} from 'recharts';

const OverviewDashboard: React.FC = () => {
  const navigate = useNavigate();
  const { user, logout } = useAuth();
  const [overview, setOverview] = useState<any>(null);
  const [anomalyTrends, setAnomalyTrends] = useState<any>(null);
  const [topThreats, setTopThreats] = useState<any>(null);
  const [advancedViz, setAdvancedViz] = useState<any>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [isLoadingAdvanced, setIsLoadingAdvanced] = useState(false);

  useEffect(() => {
    loadDashboardData();
  }, []);

  const loadDashboardData = async () => {
    setIsLoading(true);
    try {
      const [overviewData, trendsData, threatsData] = await Promise.all([
        dashboardApi.getOverview(),
        dashboardApi.getAnomalyTrends(),
        dashboardApi.getTopThreats(),
      ]);

      if (overviewData) {
        setOverview(overviewData);
      }
      if (trendsData) {
        setAnomalyTrends(trendsData);
      }
      if (threatsData) {
        setTopThreats(threatsData);
      }

      // Load advanced visualizations if we have files
      if (overviewData?.recent_activity && Array.isArray(overviewData.recent_activity) && overviewData.recent_activity.length > 0) {
        const firstFile = overviewData.recent_activity[0];
        if (firstFile?.id) {
          loadAdvancedVisualizations(firstFile.id);
        }
      }
    } catch (error) {
      console.error('Failed to load dashboard data:', error);
      // Set empty states to prevent undefined errors
      setOverview(null);
      setAnomalyTrends(null);
      setTopThreats(null);
    } finally {
      setIsLoading(false);
    }
  };

  const loadAdvancedVisualizations = async (logFileId: string) => {
    if (!logFileId) {
      setIsLoadingAdvanced(false);
      return;
    }

    setIsLoadingAdvanced(true);
    try {
      const vizData = await visualizationApi.getAllVisualizations(logFileId);
      if (vizData) {
        setAdvancedViz(vizData);
      }
    } catch (error) {
      console.error('Failed to load advanced visualizations:', error);
      setAdvancedViz(null);
    } finally {
      setIsLoadingAdvanced(false);
    }
  };

  const SEVERITY_COLORS = {
    critical: '#dc2626',
    high: '#f59e0b',
    medium: '#fbbf24',
    low: '#22c55e',
  };

  if (isLoading) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 flex items-center justify-center">
        <div className="text-center">
          <div className="inline-block animate-spin rounded-full h-12 w-12 border-b-2 border-primary-500"></div>
          <p className="mt-4 text-gray-400">Loading dashboard...</p>
        </div>
      </div>
    );
  }

  if (!overview) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 flex items-center justify-center">
        <div className="text-center">
          <AlertTriangle className="h-16 w-16 text-warning-400 mx-auto mb-4" />
          <p className="text-gray-400">Failed to load dashboard data</p>
          <button
            onClick={loadDashboardData}
            className="mt-4 px-4 py-2 bg-primary-600 hover:bg-primary-700 text-white rounded-lg"
          >
            Retry
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900">
      <NavigationBar />

      {/* Main Content */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Refresh Button */}
        <div className="mb-6 flex justify-end">
          <button
            onClick={loadDashboardData}
            disabled={isLoading}
            className="flex items-center space-x-2 px-4 py-2 bg-slate-700 hover:bg-slate-600 text-white rounded-lg transition-colors disabled:opacity-50"
          >
            <RefreshCw className={`h-4 w-4 ${isLoading ? 'animate-spin' : ''}`} />
            <span>Refresh</span>
          </button>
        </div>

        {/* Key Metrics Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
          {/* Total Files */}
          <div
            className="card cursor-pointer hover:bg-slate-700/50 transition-all duration-200 hover:scale-105"
            onClick={() => navigate('/dashboard')}
            title="Click to view all log files"
          >
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-gray-400 mb-1">Total Log Files</p>
                <p className="text-3xl font-bold text-white">{overview?.total_files ?? 0}</p>
              </div>
              <div className="bg-blue-900/50 p-3 rounded-lg">
                <FileText className="h-8 w-8 text-blue-400" />
              </div>
            </div>
          </div>

          {/* Total Entries */}
          <div className="card">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-gray-400 mb-1">Total Log Entries</p>
                <p className="text-3xl font-bold text-white">{overview.total_entries.toLocaleString()}</p>
              </div>
              <div className="bg-purple-900/50 p-3 rounded-lg">
                <Activity className="h-8 w-8 text-purple-400" />
              </div>
            </div>
          </div>

          {/* Total Anomalies */}
          <div
            className="card cursor-pointer hover:bg-slate-700/50 transition-all duration-200 hover:scale-105"
            onClick={() => navigate('/unified-analysis')}
            title="Click to view all anomalies across all files"
          >
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-gray-400 mb-1">Total Anomalies</p>
                <p className="text-3xl font-bold text-white">{overview.total_anomalies.toLocaleString()}</p>
                <p className="text-xs text-danger-400 mt-1">
                  {overview.critical_anomalies} critical
                </p>
              </div>
              <div className="bg-red-900/50 p-3 rounded-lg">
                <AlertTriangle className="h-8 w-8 text-red-400" />
              </div>
            </div>
          </div>

          {/* Avg Risk Score */}
          <div className="card">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-gray-400 mb-1">Avg Risk Score</p>
                <p className="text-3xl font-bold text-white">{overview.avg_risk_score.toFixed(1)}</p>
                <p className="text-xs text-gray-400 mt-1">
                  {overview.high_risk_entries} high-risk entries
                </p>
              </div>
              <div className="bg-orange-900/50 p-3 rounded-lg">
                <TrendingUp className="h-8 w-8 text-orange-400" />
              </div>
            </div>
          </div>

          {/* Unique Users */}
          <div className="card">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-gray-400 mb-1">Unique Users</p>
                <p className="text-3xl font-bold text-white">{overview.unique_users}</p>
              </div>
              <div className="bg-green-900/50 p-3 rounded-lg">
                <Users className="h-8 w-8 text-green-400" />
              </div>
            </div>
          </div>

          {/* Unique IPs */}
          <div className="card">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-gray-400 mb-1">Unique IPs</p>
                <p className="text-3xl font-bold text-white">{overview.unique_ips}</p>
              </div>
              <div className="bg-cyan-900/50 p-3 rounded-lg">
                <Globe className="h-8 w-8 text-cyan-400" />
              </div>
            </div>
          </div>

          {/* Threats Detected */}
          <div
            className="card cursor-pointer hover:bg-slate-700/50 transition-all duration-200 hover:scale-105"
            onClick={() => navigate('/unified-analysis?min_risk=70')}
            title="Click to view all high-risk entries across all files"
          >
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-gray-400 mb-1">Threats Detected</p>
                <p className="text-3xl font-bold text-white">{overview.threat_count}</p>
              </div>
              <div className="bg-red-900/50 p-3 rounded-lg">
                <Shield className="h-8 w-8 text-red-400" />
              </div>
            </div>
          </div>

          {/* Files by Status */}
          <div className="card">
            <div>
              <p className="text-sm text-gray-400 mb-2">Files by Status</p>
              <div className="space-y-1">
                {Object.entries(overview.files_by_status).map(([status, count]: [string, any]) => (
                  <div key={status} className="flex justify-between text-sm">
                    <span className="text-gray-300 capitalize">{status}:</span>
                    <span className="text-white font-medium">{count}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>

        {/* Anomaly Trends Over Time */}
        {anomalyTrends && anomalyTrends.time_series.length > 0 && (
          <div className="card mb-8">
            <h3 className="text-lg font-bold text-white mb-4">Anomaly Trends Over Time</h3>
            <ResponsiveContainer width="100%" height={300}>
              <AreaChart data={anomalyTrends.time_series}>
                <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                <XAxis
                  dataKey="timestamp"
                  stroke="#9ca3af"
                  tick={{ fill: '#9ca3af' }}
                  tickFormatter={(value) => new Date(value).toLocaleString([], {
                    month: 'short',
                    day: 'numeric',
                    hour: '2-digit',
                  })}
                />
                <YAxis stroke="#9ca3af" tick={{ fill: '#9ca3af' }} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#1e293b',
                    border: '1px solid #475569',
                    borderRadius: '8px',
                  }}
                  labelStyle={{ color: '#f1f5f9' }}
                />
                <Legend />
                <Area
                  type="monotone"
                  dataKey="critical"
                  stackId="1"
                  stroke="#dc2626"
                  fill="#dc2626"
                  name="Critical"
                />
                <Area
                  type="monotone"
                  dataKey="high"
                  stackId="1"
                  stroke="#f59e0b"
                  fill="#f59e0b"
                  name="High"
                />
                <Area
                  type="monotone"
                  dataKey="medium"
                  stackId="1"
                  stroke="#fbbf24"
                  fill="#fbbf24"
                  name="Medium"
                />
                <Area
                  type="monotone"
                  dataKey="low"
                  stackId="1"
                  stroke="#22c55e"
                  fill="#22c55e"
                  name="Low"
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        )}

        {/* Two Column Layout for Charts */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
          {/* Anomalies by Severity */}
          {anomalyTrends && Object.keys(anomalyTrends.by_severity).length > 0 && (
            <div className="card">
              <h3 className="text-lg font-bold text-white mb-4">Anomalies by Severity</h3>
              <ResponsiveContainer width="100%" height={300}>
                <RechartsPieChart>
                  <Pie
                    data={Object.entries(anomalyTrends.by_severity).map(([severity, count]) => ({
                      name: severity.charAt(0).toUpperCase() + severity.slice(1),
                      value: count,
                    }))}
                    cx="50%"
                    cy="50%"
                    labelLine={false}
                    label={({ name, percent }) => `${name}: ${(percent * 100).toFixed(0)}%`}
                    outerRadius={100}
                    fill="#8884d8"
                    dataKey="value"
                  >
                    {Object.keys(anomalyTrends.by_severity).map((severity) => (
                      <Cell
                        key={severity}
                        fill={SEVERITY_COLORS[severity as keyof typeof SEVERITY_COLORS]}
                      />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#1e293b',
                      border: '1px solid #475569',
                      borderRadius: '8px',
                    }}
                  />
                </RechartsPieChart>
              </ResponsiveContainer>
            </div>
          )}

          {/* Top Anomaly Types */}
          {anomalyTrends && anomalyTrends.by_type.length > 0 && (
            <div className="card">
              <h3 className="text-lg font-bold text-white mb-4">Top Anomaly Types</h3>
              <ResponsiveContainer width="100%" height={300}>
                <BarChart data={anomalyTrends.by_type}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                  <XAxis
                    dataKey="type"
                    stroke="#9ca3af"
                    tick={{ fill: '#9ca3af', fontSize: 11 }}
                    angle={-45}
                    textAnchor="end"
                    height={100}
                  />
                  <YAxis stroke="#9ca3af" tick={{ fill: '#9ca3af' }} />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#1e293b',
                      border: '1px solid #475569',
                      borderRadius: '8px',
                    }}
                  />
                  <Bar dataKey="count" fill="#0ea5e9" name="Count" />
                </BarChart>
              </ResponsiveContainer>
            </div>
          )}
        </div>

        {/* Top Threats Section */}
        {topThreats && (
          <>
            {/* Top Threats and Categories */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
              {/* Top Threats */}
              {topThreats.threats.length > 0 && (
                <div className="card">
                  <h3 className="text-lg font-bold text-white mb-4">Top Threats Detected</h3>
                  <div className="space-y-3">
                    {topThreats.threats.slice(0, 5).map((threat: any, index: number) => (
                      <div
                        key={index}
                        className="flex items-center justify-between p-3 bg-slate-700/50 rounded-lg cursor-pointer hover:bg-slate-600/50 transition-colors"
                        onClick={() => navigate(`/unified-analysis?threat_name=${encodeURIComponent(threat.name)}`)}
                        title={`Click to view all entries for threat: ${threat.name}`}
                      >
                        <div className="flex-1">
                          <p className="text-white font-medium text-sm">{threat.name}</p>
                          <p className="text-xs text-gray-400 mt-1">
                            {threat.count} occurrences • Avg Risk: {threat.avg_risk.toFixed(1)}
                          </p>
                        </div>
                        <div className="ml-4">
                          <div
                            className={`px-3 py-1 rounded text-xs font-medium ${
                              threat.avg_risk >= 70
                                ? 'bg-red-900 text-red-200'
                                : threat.avg_risk >= 40
                                ? 'bg-orange-900 text-orange-200'
                                : 'bg-yellow-900 text-yellow-200'
                            }`}
                          >
                            {threat.avg_risk.toFixed(0)}
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Top Risky Categories */}
              {topThreats.categories.length > 0 && (
                <div className="card">
                  <h3 className="text-lg font-bold text-white mb-4">Top Risky Categories</h3>
                  <ResponsiveContainer width="100%" height={250}>
                    <BarChart data={topThreats.categories.slice(0, 8)} layout="vertical">
                      <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                      <XAxis type="number" stroke="#9ca3af" tick={{ fill: '#9ca3af' }} />
                      <YAxis
                        type="category"
                        dataKey="category"
                        stroke="#9ca3af"
                        tick={{ fill: '#9ca3af', fontSize: 11 }}
                        width={120}
                      />
                      <Tooltip
                        contentStyle={{
                          backgroundColor: '#1e293b',
                          border: '1px solid #475569',
                          borderRadius: '8px',
                        }}
                      />
                      <Bar dataKey="avg_risk" fill="#f59e0b" name="Avg Risk Score" />
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              )}
            </div>

            {/* Top Risky Users and IPs */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
              {/* Top Risky Users */}
              {topThreats.users.length > 0 && (
                <div className="card">
                  <h3 className="text-lg font-bold text-white mb-4">Top Risky Users</h3>
                  <div className="overflow-x-auto">
                    <table className="w-full">
                      <thead>
                        <tr className="border-b border-slate-700">
                          <th className="text-left py-2 px-3 text-xs font-medium text-gray-400">
                            Username
                          </th>
                          <th className="text-right py-2 px-3 text-xs font-medium text-gray-400">
                            Events
                          </th>
                          <th className="text-right py-2 px-3 text-xs font-medium text-gray-400">
                            Avg Risk
                          </th>
                          <th className="text-right py-2 px-3 text-xs font-medium text-gray-400">
                            Max Risk
                          </th>
                        </tr>
                      </thead>
                      <tbody>
                        {topThreats.users.slice(0, 8).map((user: any, index: number) => (
                          <tr
                            key={index}
                            className="border-b border-slate-700/50 cursor-pointer hover:bg-slate-700/30 transition-colors"
                            onClick={() => navigate(`/unified-analysis?username=${encodeURIComponent(user.username)}`)}
                            title={`Click to view all entries for user: ${user.username}`}
                          >
                            <td className="py-2 px-3 text-sm text-white">{user.username}</td>
                            <td className="py-2 px-3 text-sm text-gray-300 text-right">
                              {user.count}
                            </td>
                            <td className="py-2 px-3 text-sm text-right">
                              <span
                                className={`px-2 py-1 rounded text-xs font-medium ${
                                  user.avg_risk >= 70
                                    ? 'bg-red-900 text-red-200'
                                    : user.avg_risk >= 40
                                    ? 'bg-orange-900 text-orange-200'
                                    : 'bg-yellow-900 text-yellow-200'
                                }`}
                              >
                                {user.avg_risk.toFixed(1)}
                              </span>
                            </td>
                            <td className="py-2 px-3 text-sm text-right">
                              <span className="text-red-400 font-medium">
                                {user.max_risk.toFixed(0)}
                              </span>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}

              {/* Top Risky IPs */}
              {topThreats.ips.length > 0 && (
                <div className="card">
                  <h3 className="text-lg font-bold text-white mb-4">Top Risky IP Addresses</h3>
                  <div className="overflow-x-auto">
                    <table className="w-full">
                      <thead>
                        <tr className="border-b border-slate-700">
                          <th className="text-left py-2 px-3 text-xs font-medium text-gray-400">
                            IP Address
                          </th>
                          <th className="text-right py-2 px-3 text-xs font-medium text-gray-400">
                            Events
                          </th>
                          <th className="text-right py-2 px-3 text-xs font-medium text-gray-400">
                            Avg Risk
                          </th>
                          <th className="text-right py-2 px-3 text-xs font-medium text-gray-400">
                            Max Risk
                          </th>
                        </tr>
                      </thead>
                      <tbody>
                        {topThreats.ips.slice(0, 8).map((ip: any, index: number) => (
                          <tr
                            key={index}
                            className="border-b border-slate-700/50 cursor-pointer hover:bg-slate-700/30 transition-colors"
                            onClick={() => navigate(`/unified-analysis?ip=${encodeURIComponent(ip.ip)}`)}
                            title={`Click to view all entries for IP: ${ip.ip}`}
                          >
                            <td className="py-2 px-3 text-sm text-white font-mono">{ip.ip}</td>
                            <td className="py-2 px-3 text-sm text-gray-300 text-right">
                              {ip.count}
                            </td>
                            <td className="py-2 px-3 text-sm text-right">
                              <span
                                className={`px-2 py-1 rounded text-xs font-medium ${
                                  ip.avg_risk >= 70
                                    ? 'bg-red-900 text-red-200'
                                    : ip.avg_risk >= 40
                                    ? 'bg-orange-900 text-orange-200'
                                    : 'bg-yellow-900 text-yellow-200'
                                }`}
                              >
                                {ip.avg_risk.toFixed(1)}
                              </span>
                            </td>
                            <td className="py-2 px-3 text-sm text-right">
                              <span className="text-red-400 font-medium">
                                {ip.max_risk.toFixed(0)}
                              </span>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}
            </div>
          </>
        )}

        {/* Recent Activity Section */}
        {overview.recent_activity && overview.recent_activity.length > 0 && (
          <div className="mb-8">
            <h3 className="text-lg font-bold text-white mb-4">Recent Log Files</h3>
            <div className="card">
              <div className="overflow-x-auto">
                <table className="w-full">
                  <thead>
                    <tr className="border-b border-slate-700">
                      <th className="text-left py-3 px-4 text-xs font-medium text-gray-400">
                        Filename
                      </th>
                      <th className="text-left py-3 px-4 text-xs font-medium text-gray-400">
                        Status
                      </th>
                      <th className="text-right py-3 px-4 text-xs font-medium text-gray-400">
                        Entries
                      </th>
                      <th className="text-right py-3 px-4 text-xs font-medium text-gray-400">
                        Anomalies
                      </th>
                      <th className="text-left py-3 px-4 text-xs font-medium text-gray-400">
                        Uploaded
                      </th>
                    </tr>
                  </thead>
                  <tbody>
                    {overview.recent_activity.slice(0, 10).map((file: any) => (
                      <tr
                        key={file.id}
                        className="border-b border-slate-700/50 cursor-pointer hover:bg-slate-700/30 transition-colors"
                        onClick={() => navigate(`/analysis/${file.id}`)}
                        title={`Click to view analysis for ${file.filename}`}
                      >
                        <td className="py-3 px-4 text-sm text-white">
                          <div className="flex items-center space-x-2">
                            <FileText className="h-4 w-4 text-blue-400" />
                            <span className="font-medium">{file.filename}</span>
                          </div>
                        </td>
                        <td className="py-3 px-4 text-sm">
                          <span
                            className={`px-2 py-1 rounded text-xs font-medium ${
                              file.status === 'completed'
                                ? 'bg-green-900 text-green-200'
                                : file.status === 'processing'
                                ? 'bg-yellow-900 text-yellow-200'
                                : file.status === 'failed'
                                ? 'bg-red-900 text-red-200'
                                : 'bg-gray-900 text-gray-200'
                            }`}
                          >
                            {file.status}
                          </span>
                        </td>
                        <td className="py-3 px-4 text-sm text-gray-300 text-right">
                          {file.total_entries?.toLocaleString() || 0}
                        </td>
                        <td className="py-3 px-4 text-sm text-right">
                          <span className="text-red-400 font-medium">
                            {file.anomaly_count || 0}
                          </span>
                        </td>
                        <td className="py-3 px-4 text-sm text-gray-400">
                          {new Date(file.uploaded_at).toLocaleString([], {
                            month: 'short',
                            day: 'numeric',
                            hour: '2-digit',
                            minute: '2-digit',
                          })}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        )}

        {/* Advanced Analytics Section */}
        <div className="mt-8">
          <div className="flex items-center justify-between mb-6">
            <div className="flex items-center space-x-3">
              <div className="bg-purple-900/50 p-2 rounded-lg">
                <Sparkles className="h-6 w-6 text-purple-400" />
              </div>
              <div>
                <h2 className="text-2xl font-bold text-white">Advanced Analytics</h2>
                <p className="text-sm text-gray-400">
                  Statistical analysis and pattern detection from most recent log file
                </p>
              </div>
            </div>
          </div>

          {isLoadingAdvanced ? (
            <div className="card">
              <div className="text-center py-12">
                <div className="inline-block animate-spin rounded-full h-8 w-8 border-b-2 border-purple-500"></div>
                <p className="mt-4 text-gray-400">Loading advanced analytics...</p>
              </div>
            </div>
          ) : !advancedViz ? (
            <div className="card">
              <div className="text-center py-12">
                <Sparkles className="h-16 w-16 text-gray-600 mx-auto mb-4" />
                <p className="text-gray-400">No log files available for analysis</p>
                <p className="text-sm text-gray-500 mt-2">Upload a log file to see advanced analytics</p>
              </div>
            </div>
          ) : (
            <div>

            {/* Z-Score Heatmap */}
            {advancedViz.z_score_heatmap && advancedViz.z_score_heatmap.users && advancedViz.z_score_heatmap.z_scores && advancedViz.z_score_heatmap.users.length > 0 && (
              <div className="card mb-6">
                <h3 className="text-lg font-bold text-white mb-4">User Activity Heatmap (Z-Score)</h3>
                <p className="text-sm text-gray-400 mb-4">
                  Hourly user activity patterns - darker colors indicate higher anomaly scores
                </p>
                <div className="overflow-x-auto">
                  <table className="w-full text-xs">
                    <thead>
                      <tr className="border-b border-slate-700">
                        <th className="text-left py-2 px-2 text-gray-400 font-medium">User</th>
                        {advancedViz.z_score_heatmap.time_buckets && advancedViz.z_score_heatmap.time_buckets.slice(0, 24).map((bucket: string, idx: number) => (
                          <th key={idx} className="text-center py-2 px-1 text-gray-400 font-medium">
                            {new Date(bucket).getHours()}h
                          </th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {advancedViz.z_score_heatmap.users.slice(0, 10).map((user: string, userIdx: number) => {
                        const userScores = advancedViz.z_score_heatmap.z_scores[userIdx] || [];
                        return (
                          <tr key={userIdx} className="border-b border-slate-700/50">
                            <td className="py-2 px-2 text-white font-medium">{user}</td>
                            {userScores.slice(0, 24).map((value: number, hourIdx: number) => (
                              <td
                                key={hourIdx}
                                className="py-2 px-1 text-center"
                                style={{
                                  backgroundColor: value > 2
                                    ? '#dc2626'
                                    : value > 1
                                    ? '#f59e0b'
                                    : value > 0.5
                                    ? '#fbbf24'
                                    : value > 0
                                    ? '#22c55e'
                                    : '#1e293b',
                                  color: value > 0.5 ? '#fff' : '#9ca3af',
                                }}
                              >
                                {value > 0 ? value.toFixed(1) : '-'}
                              </td>
                            ))}
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              </div>
            )}

            {/* Statistical Visualizations Grid */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
              {/* Box Plot */}
              {advancedViz.boxplot_per_user && advancedViz.boxplot_per_user.boxplots && advancedViz.boxplot_per_user.boxplots.length > 0 && (
                <div className="card">
                  <h3 className="text-lg font-bold text-white mb-4">Risk Score Distribution by User</h3>
                  <ResponsiveContainer width="100%" height={300}>
                    <BarChart data={advancedViz.boxplot_per_user.boxplots.slice(0, 10)}>
                      <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                      <XAxis
                        dataKey="user"
                        stroke="#9ca3af"
                        tick={{ fill: '#9ca3af', fontSize: 10 }}
                        angle={-45}
                        textAnchor="end"
                        height={80}
                      />
                      <YAxis stroke="#9ca3af" tick={{ fill: '#9ca3af' }} />
                      <Tooltip
                        contentStyle={{
                          backgroundColor: '#1e293b',
                          border: '1px solid #475569',
                          borderRadius: '8px',
                        }}
                      />
                      <Bar dataKey="median" fill="#0ea5e9" name="Median Risk" />
                      <Bar dataKey="q3" fill="#f59e0b" name="75th Percentile" />
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              )}

              {/* Density Plot */}
              {advancedViz.density_plot && advancedViz.density_plot.normal && advancedViz.density_plot.normal.values && advancedViz.density_plot.normal.values.length > 0 && (
                <div className="card">
                  <h3 className="text-lg font-bold text-white mb-4">Risk Score Density Distribution</h3>
                  <ResponsiveContainer width="100%" height={300}>
                    <AreaChart data={advancedViz.density_plot.normal.values.map((v: number, i: number) => ({ value: v, density: advancedViz.density_plot.normal.densities[i] }))}>
                      <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                      <XAxis
                        dataKey="value"
                        stroke="#9ca3af"
                        tick={{ fill: '#9ca3af' }}
                        label={{ value: 'Risk Score', position: 'insideBottom', offset: -5, fill: '#9ca3af' }}
                      />
                      <YAxis
                        stroke="#9ca3af"
                        tick={{ fill: '#9ca3af' }}
                        label={{ value: 'Density', angle: -90, position: 'insideLeft', fill: '#9ca3af' }}
                      />
                      <Tooltip
                        contentStyle={{
                          backgroundColor: '#1e293b',
                          border: '1px solid #475569',
                          borderRadius: '8px',
                        }}
                      />
                      <Area
                        type="monotone"
                        dataKey="density"
                        stroke="#8b5cf6"
                        fill="#8b5cf6"
                        fillOpacity={0.6}
                        name="Probability Density"
                      />
                    </AreaChart>
                  </ResponsiveContainer>
                </div>
              )}
            </div>

            {/* Anomaly Scatter Plot */}
            {advancedViz.anomaly_scatter && advancedViz.anomaly_scatter.timestamps && advancedViz.anomaly_scatter.timestamps.length > 0 && (
              <div className="card mb-6">
                <h3 className="text-lg font-bold text-white mb-4">Anomaly Risk Score Timeline</h3>
                <ResponsiveContainer width="100%" height={300}>
                  <LineChart data={advancedViz.anomaly_scatter.timestamps.map((t: string, i: number) => ({ timestamp: t, risk_score: advancedViz.anomaly_scatter.x[i] }))}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                    <XAxis
                      dataKey="timestamp"
                      stroke="#9ca3af"
                      tick={{ fill: '#9ca3af', fontSize: 10 }}
                      tickFormatter={(value) =>
                        new Date(value).toLocaleString([], {
                          month: 'short',
                          day: 'numeric',
                          hour: '2-digit',
                        })
                      }
                    />
                    <YAxis stroke="#9ca3af" tick={{ fill: '#9ca3af' }} label={{ value: 'Risk Score', angle: -90, position: 'insideLeft', fill: '#9ca3af' }} />
                    <Tooltip
                      contentStyle={{
                        backgroundColor: '#1e293b',
                        border: '1px solid #475569',
                        borderRadius: '8px',
                      }}
                      labelFormatter={(value) => new Date(value).toLocaleString()}
                    />
                    <Legend />
                    <Line
                      type="monotone"
                      dataKey="risk_score"
                      stroke="#dc2626"
                      strokeWidth={2}
                      dot={{ fill: '#dc2626', r: 3 }}
                      name="Risk Score"
                    />
                  </LineChart>
                </ResponsiveContainer>
              </div>
            )}
            </div>
          )}
        </div>
      </main>
    </div>
  );
};

export default OverviewDashboard;

