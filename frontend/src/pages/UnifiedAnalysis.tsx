import React, { useState, useEffect } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { dashboardApi } from '../services/api';
import NavigationBar from '../components/NavigationBar';
import {
  ArrowLeft,
  Filter,
  AlertTriangle,
  Activity,
  FileText,
  TrendingUp,
} from 'lucide-react';

const UnifiedAnalysis: React.FC = () => {
  const navigate = useNavigate();
  const { } = useAuth();
  const [searchParams] = useSearchParams();
  
  const [data, setData] = useState<any>(null);
  const [isLoading, setIsLoading] = useState(true);
  
  // Get filters from URL params
  const filters = {
    username: searchParams.get('username') || undefined,
    ip: searchParams.get('ip') || undefined,
    threat_name: searchParams.get('threat_name') || undefined,
    category: searchParams.get('category') || undefined,
    min_risk: searchParams.get('min_risk') ? parseFloat(searchParams.get('min_risk')!) : undefined,
  };

  useEffect(() => {
    loadData();
  }, [searchParams]);

  const loadData = async () => {
    setIsLoading(true);
    try {
      const result = await dashboardApi.getUnifiedAnalysis(filters);
      setData(result);
    } catch (error) {
      console.error('Failed to load unified analysis:', error);
    } finally {
      setIsLoading(false);
    }
  };

  const getRiskColor = (risk: number) => {
    if (risk >= 80) return 'text-red-400';
    if (risk >= 60) return 'text-orange-400';
    if (risk >= 40) return 'text-yellow-400';
    return 'text-green-400';
  };

  const getRiskBadgeColor = (risk: number) => {
    if (risk >= 80) return 'bg-red-900/50 text-red-400';
    if (risk >= 60) return 'bg-orange-900/50 text-orange-400';
    if (risk >= 40) return 'bg-yellow-900/50 text-yellow-400';
    return 'bg-green-900/50 text-green-400';
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'text-red-400';
      case 'high': return 'text-orange-400';
      case 'medium': return 'text-yellow-400';
      case 'low': return 'text-blue-400';
      default: return 'text-gray-400';
    }
  };

  if (isLoading) {
    return (
      <div className="min-h-screen bg-slate-900">
        <NavigationBar />
        <main className="container mx-auto px-4 py-8">
          <div className="flex items-center justify-center h-64">
            <div className="text-white text-xl">Loading unified analysis...</div>
          </div>
        </main>
      </div>
    );
  }

  if (!data) {
    return (
      <div className="min-h-screen bg-slate-900">
        <NavigationBar />
        <main className="container mx-auto px-4 py-8">
          <div className="flex items-center justify-center h-64">
            <div className="text-white text-xl">No data available</div>
          </div>
        </main>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-slate-900">
      <NavigationBar />
      
      <main className="container mx-auto px-4 py-8">
        {/* Header */}
        <div className="mb-8">
          <button
            onClick={() => navigate('/overview')}
            className="flex items-center text-gray-400 hover:text-white mb-4 transition-colors"
          >
            <ArrowLeft className="h-4 w-4 mr-2" />
            Back to Overview
          </button>
          
          <h1 className="text-3xl font-bold text-white mb-2">Unified Analysis</h1>
          <p className="text-gray-400">Analysis across all log files</p>
        </div>

        {/* Active Filters */}
        {Object.keys(data.filters_applied).length > 0 && (
          <div className="card mb-6">
            <div className="flex items-center mb-3">
              <Filter className="h-5 w-5 text-blue-400 mr-2" />
              <h3 className="text-lg font-bold text-white">Active Filters</h3>
            </div>
            <div className="flex flex-wrap gap-2">
              {Object.entries(data.filters_applied).map(([key, value]) => (
                <span
                  key={key}
                  className="px-3 py-1 bg-blue-900/50 text-blue-400 rounded-full text-sm"
                >
                  {key}: <strong>{String(value)}</strong>
                </span>
              ))}
            </div>
          </div>
        )}

        {/* Statistics Cards */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
          {/* Total Entries */}
          <div className="card">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-gray-400 mb-1">Total Entries</p>
                <p className="text-3xl font-bold text-white">{data.statistics.total_count.toLocaleString()}</p>
              </div>
              <div className="bg-blue-900/50 p-3 rounded-lg">
                <FileText className="h-8 w-8 text-blue-400" />
              </div>
            </div>
          </div>

          {/* Anomalies */}
          <div className="card">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-gray-400 mb-1">Anomalies</p>
                <p className="text-3xl font-bold text-white">{data.statistics.anomaly_count}</p>
              </div>
              <div className="bg-red-900/50 p-3 rounded-lg">
                <AlertTriangle className="h-8 w-8 text-red-400" />
              </div>
            </div>
          </div>

          {/* High Risk Entries */}
          <div className="card">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-gray-400 mb-1">High Risk</p>
                <p className="text-3xl font-bold text-white">{data.statistics.high_risk_count}</p>
                <p className="text-xs text-gray-400 mt-1">Risk ≥ 70</p>
              </div>
              <div className="bg-orange-900/50 p-3 rounded-lg">
                <TrendingUp className="h-8 w-8 text-orange-400" />
              </div>
            </div>
          </div>

          {/* Average Risk */}
          <div className="card">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-gray-400 mb-1">Avg Risk Score</p>
                <p className={`text-3xl font-bold ${getRiskColor(data.statistics.avg_risk_score)}`}>
                  {data.statistics.avg_risk_score.toFixed(1)}
                </p>
              </div>
              <div className="bg-purple-900/50 p-3 rounded-lg">
                <Activity className="h-8 w-8 text-purple-400" />
              </div>
            </div>
          </div>
        </div>

        {/* File Breakdown */}
        {Object.keys(data.statistics.file_breakdown).length > 0 && (
          <div className="card mb-8">
            <h3 className="text-lg font-bold text-white mb-4">File Breakdown</h3>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {Object.entries(data.statistics.file_breakdown).map(([filename, count]) => (
                <div key={filename} className="bg-slate-700/30 p-3 rounded-lg">
                  <p className="text-sm text-gray-400 truncate">{filename}</p>
                  <p className="text-xl font-bold text-white">{count as number} entries</p>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Anomalies Table */}
        {data.anomalies.length > 0 && (
          <div className="card mb-8">
            <h3 className="text-lg font-bold text-white mb-4">Anomalies Detected</h3>
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="border-b border-slate-700">
                    <th className="text-left py-3 px-4 text-gray-400 font-semibold">Type</th>
                    <th className="text-left py-3 px-4 text-gray-400 font-semibold">Severity</th>
                    <th className="text-left py-3 px-4 text-gray-400 font-semibold">Description</th>
                    <th className="text-left py-3 px-4 text-gray-400 font-semibold">Confidence</th>
                  </tr>
                </thead>
                <tbody>
                  {data.anomalies.map((anomaly: any, index: number) => (
                    <tr key={index} className="border-b border-slate-700/50 hover:bg-slate-700/30 transition-colors">
                      <td className="py-3 px-4 text-white">{anomaly.anomaly_type}</td>
                      <td className="py-3 px-4">
                        <span className={`font-semibold ${getSeverityColor(anomaly.severity)}`}>
                          {anomaly.severity}
                        </span>
                      </td>
                      <td className="py-3 px-4 text-gray-300">{anomaly.description}</td>
                      <td className="py-3 px-4 text-gray-300">{(anomaly.confidence_score * 100).toFixed(0)}%</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* Log Entries Table */}
        {data.log_entries.length > 0 && (
          <div className="card">
            <h3 className="text-lg font-bold text-white mb-4">
              Log Entries ({data.log_entries.length} of {data.statistics.total_count})
            </h3>
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="border-b border-slate-700">
                    <th className="text-left py-3 px-4 text-gray-400 font-semibold">Timestamp</th>
                    <th className="text-left py-3 px-4 text-gray-400 font-semibold">User</th>
                    <th className="text-left py-3 px-4 text-gray-400 font-semibold">IP</th>
                    <th className="text-left py-3 px-4 text-gray-400 font-semibold">URL</th>
                    <th className="text-left py-3 px-4 text-gray-400 font-semibold">Risk</th>
                    <th className="text-left py-3 px-4 text-gray-400 font-semibold">Threat</th>
                  </tr>
                </thead>
                <tbody>
                  {data.log_entries.map((entry: any, index: number) => (
                    <tr key={index} className="border-b border-slate-700/50 hover:bg-slate-700/30 transition-colors">
                      <td className="py-3 px-4 text-gray-300 text-sm">
                        {new Date(entry.timestamp).toLocaleString()}
                      </td>
                      <td className="py-3 px-4 text-white">{entry.username || '-'}</td>
                      <td className="py-3 px-4 text-gray-300">{entry.source_ip || '-'}</td>
                      <td className="py-3 px-4 text-gray-300 max-w-xs truncate">{entry.url || '-'}</td>
                      <td className="py-3 px-4">
                        <span className={`px-2 py-1 rounded text-sm font-semibold ${getRiskBadgeColor(entry.risk_score || 0)}`}>
                          {entry.risk_score?.toFixed(0) || 0}
                        </span>
                      </td>
                      <td className="py-3 px-4 text-red-400">{entry.threat_name || '-'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {data.log_entries.length === 0 && (
          <div className="card text-center py-12">
            <p className="text-gray-400 text-lg">No log entries found matching the filters</p>
          </div>
        )}
      </main>
    </div>
  );
};

export default UnifiedAnalysis;

