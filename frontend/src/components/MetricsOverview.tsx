import React, { useState } from 'react';
import {
  AlertTriangle,
  Shield,
  Clock,
  Activity,
  Globe,
  Users,
  Ban,
  CheckCircle,
  TrendingUp,
  Database,
} from 'lucide-react';
import MetricsCard from './MetricsCard';
import DataTableModal from './DataTableModal';
import LogEntryDetails from './LogEntryDetails';
import { anomalyApi, logEntriesApi } from '../services/api';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';

interface MetricsOverviewProps {
  statistics: {
    total_entries: number;
    threat_count: number;
    high_risk_count: number;
    bypassed_count: number;
    unique_users: number;
    unique_source_ips: number;
    unique_dest_ips: number;
    blocked_count: number;
    allowed_count: number;
    total_bytes: number;
    total_bytes_sent: number;
    total_bytes_received: number;
    action_breakdown: Array<{ action: string; count: number }>;
  };
  anomalyStatistics: {
    total: number;
    by_severity: {
      critical?: number;
      high?: number;
      medium?: number;
      low?: number;
    };
  };
  logFile: {
    id: string;
    created_at: string;
    processed_at?: string | null;
  };
}

type ModalType =
  | 'alerts'
  | 'critical_alerts'
  | 'log_volume'
  | 'source_ips'
  | 'dest_ips'
  | 'users'
  | 'blocked'
  | 'allowed'
  | 'threats'
  | 'bypassed'
  | null;

const MetricsOverview: React.FC<MetricsOverviewProps> = ({
  statistics,
  anomalyStatistics,
  logFile,
}) => {
  const [activeModal, setActiveModal] = useState<ModalType>(null);
  // Format bytes to human-readable format
  const formatBytes = (bytes: number): string => {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return `${(bytes / Math.pow(k, i)).toFixed(2)} ${sizes[i]}`;
  };

  // Calculate MTTD (Mean Time to Detect) - simplified version
  const calculateMTTD = (): string => {
    if (!logFile.created_at || !logFile.processed_at) return 'N/A';
    const uploadTime = new Date(logFile.created_at).getTime();
    const processTime = new Date(logFile.processed_at).getTime();
    const diffSeconds = Math.floor((processTime - uploadTime) / 1000);
    
    if (diffSeconds < 60) return `${diffSeconds}s`;
    if (diffSeconds < 3600) return `${Math.floor(diffSeconds / 60)}m`;
    return `${Math.floor(diffSeconds / 3600)}h`;
  };

  // Prepare action breakdown chart data
  const actionChartData = statistics.action_breakdown.map(item => ({
    name: item.action || 'Unknown',
    count: item.count,
  }));

  // Calculate critical alerts count
  const criticalAlerts = (anomalyStatistics.by_severity.critical || 0) + 
                         (anomalyStatistics.by_severity.high || 0);

  // Calculate success rate for logins (if we have the data)
  const totalActions = statistics.blocked_count + statistics.allowed_count;
  const successRate = totalActions > 0
    ? ((statistics.allowed_count / totalActions) * 100).toFixed(1)
    : '0';

  // Data fetching functions for modals
  const fetchAnomalies = async (page: number, perPage: number, search: string) => {
    const result = await anomalyApi.getAnomalies(logFile.id, page, perPage, undefined, search);
    return {
      data: result.anomalies,
      total: result.total,
      page: result.page,
      per_page: result.per_page,
      total_pages: Math.ceil(result.total / result.per_page),
    };
  };

  const fetchCriticalAnomalies = async (page: number, perPage: number, search: string) => {
    const result = await anomalyApi.getAnomalies(logFile.id, page, perPage, 'critical', search);
    return {
      data: result.anomalies,
      total: result.total,
      page: result.page,
      per_page: result.per_page,
      total_pages: Math.ceil(result.total / result.per_page),
    };
  };

  const fetchLogEntries = async (page: number, perPage: number, search: string, filterType?: string) => {
    const result = await logEntriesApi.getEntries(logFile.id, page, perPage, search, filterType);
    return {
      data: result.entries,
      total: result.total,
      page: result.page,
      per_page: result.per_page,
      total_pages: result.total_pages,
    };
  };

  const fetchUsers = async (page: number, perPage: number, search: string) => {
    const result = await logEntriesApi.getUsers(logFile.id, page, perPage, search);
    return {
      data: result.users,
      total: result.total,
      page: result.page,
      per_page: result.per_page,
      total_pages: result.total_pages,
    };
  };

  const fetchIPs = async (page: number, perPage: number, search: string, ipType: 'source' | 'destination') => {
    const result = await logEntriesApi.getIPs(logFile.id, page, perPage, search, ipType);
    return {
      data: result.ips,
      total: result.total,
      page: result.page,
      per_page: result.per_page,
      total_pages: result.total_pages,
    };
  };

  // Helper to format timestamps
  const formatTimestamp = (timestamp: string) => {
    return new Date(timestamp).toLocaleString();
  };

  // Helper to get severity badge
  const getSeverityBadge = (severity: string) => {
    const colors = {
      critical: 'bg-red-500/20 text-red-400 border border-red-500/30',
      high: 'bg-orange-500/20 text-orange-400 border border-orange-500/30',
      medium: 'bg-yellow-500/20 text-yellow-400 border border-yellow-500/30',
      low: 'bg-green-500/20 text-green-400 border border-green-500/30',
    };
    return colors[severity as keyof typeof colors] || colors.low;
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <h2 className="text-xl font-bold text-white flex items-center space-x-2">
          <Activity className="h-6 w-6 text-primary-400" />
          <span>System Metrics - At a Glance</span>
        </h2>
      </div>

      {/* Top Row - Critical Metrics */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Total Alerts */}
        <MetricsCard
          title="Total Alerts"
          value={anomalyStatistics.total}
          icon={AlertTriangle}
          color="warning"
          subtitle="Detected anomalies"
          badge={{ text: 'Last 24h', color: 'blue' }}
          clickable={true}
          onClick={() => setActiveModal('alerts')}
        />

        {/* Critical Alerts */}
        <MetricsCard
          title="Critical Alerts"
          value={criticalAlerts}
          icon={Shield}
          color="danger"
          subtitle="Immediate attention required"
          badge={{ text: 'High Priority', color: 'red' }}
          clickable={true}
          onClick={() => setActiveModal('critical_alerts')}
        />

        {/* MTTD */}
        <MetricsCard
          title="MTTD"
          value={calculateMTTD()}
          icon={Clock}
          color="info"
          subtitle="Mean Time to Detect"
          clickable={false}
        />

        {/* Log Volume */}
        <MetricsCard
          title="Log Volume"
          value={statistics.total_entries.toLocaleString()}
          icon={Database}
          color="primary"
          subtitle="Total entries processed"
          clickable={true}
          onClick={() => setActiveModal('log_volume')}
        />
      </div>

      {/* Second Row - Network & User Metrics */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Unique Source IPs */}
        <MetricsCard
          title="Unique Source IPs"
          value={statistics.unique_source_ips}
          icon={Globe}
          color="info"
          subtitle="Inbound connections"
          clickable={true}
          onClick={() => setActiveModal('source_ips')}
        />

        {/* Unique Destination IPs */}
        <MetricsCard
          title="Unique Dest IPs"
          value={statistics.unique_dest_ips}
          icon={TrendingUp}
          color="info"
          subtitle="Outbound connections"
          clickable={true}
          onClick={() => setActiveModal('dest_ips')}
        />

        {/* Unique Users */}
        <MetricsCard
          title="Unique Users"
          value={statistics.unique_users}
          icon={Users}
          color="primary"
          subtitle="Authenticated users"
          clickable={true}
          onClick={() => setActiveModal('users')}
        />

        {/* Data Volume */}
        <MetricsCard
          title="Data Transferred"
          value={formatBytes(statistics.total_bytes)}
          icon={Activity}
          color="success"
          subtitle={`↑ ${formatBytes(statistics.total_bytes_sent)} ↓ ${formatBytes(statistics.total_bytes_received)}`}
        />
      </div>

      {/* Third Row - Security Metrics */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Blocked Connections */}
        <MetricsCard
          title="Blocked Connections"
          value={statistics.blocked_count}
          icon={Ban}
          color="danger"
          subtitle={`${((statistics.blocked_count / totalActions) * 100 || 0).toFixed(1)}% of total`}
          clickable={true}
          onClick={() => setActiveModal('blocked')}
        />

        {/* Allowed Connections */}
        <MetricsCard
          title="Allowed Connections"
          value={statistics.allowed_count}
          icon={CheckCircle}
          color="success"
          subtitle={`${successRate}% success rate`}
          clickable={true}
          onClick={() => setActiveModal('allowed')}
        />

        {/* Threats Detected */}
        <MetricsCard
          title="Threats Detected"
          value={statistics.threat_count}
          icon={AlertTriangle}
          color="warning"
          subtitle="Malware & malicious activity"
          badge={statistics.threat_count > 0 ? { text: 'Active', color: 'red' } : undefined}
          clickable={true}
          onClick={() => setActiveModal('threats')}
        />

        {/* Bypassed Traffic */}
        <MetricsCard
          title="Bypassed Traffic"
          value={statistics.bypassed_count}
          icon={Shield}
          color={statistics.bypassed_count > 0 ? 'warning' : 'success'}
          subtitle="Unscanned connections"
          badge={statistics.bypassed_count > 0 ? { text: 'Review', color: 'yellow' } : undefined}
          clickable={true}
          onClick={() => setActiveModal('bypassed')}
        />
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Blocked vs Allowed Chart */}
        <div className="card">
          <h3 className="text-lg font-semibold text-white mb-4 flex items-center space-x-2">
            <Shield className="h-5 w-5 text-primary-400" />
            <span>Blocked vs Allowed Connections</span>
          </h3>
          <ResponsiveContainer width="100%" height={200}>
            <BarChart
              data={[
                { name: 'Blocked', value: statistics.blocked_count, fill: '#dc2626' },
                { name: 'Allowed', value: statistics.allowed_count, fill: '#22c55e' },
              ]}
            >
              <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
              <XAxis dataKey="name" stroke="#9ca3af" />
              <YAxis stroke="#9ca3af" />
              <Tooltip
                contentStyle={{
                  backgroundColor: '#1e293b',
                  border: '1px solid #334155',
                  borderRadius: '0.5rem',
                }}
              />
              <Bar dataKey="value" />
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* Action Breakdown Chart */}
        <div className="card">
          <h3 className="text-lg font-semibold text-white mb-4 flex items-center space-x-2">
            <Activity className="h-5 w-5 text-primary-400" />
            <span>Action Breakdown</span>
          </h3>
          <ResponsiveContainer width="100%" height={200}>
            <BarChart data={actionChartData.slice(0, 5)}>
              <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
              <XAxis dataKey="name" stroke="#9ca3af" />
              <YAxis stroke="#9ca3af" />
              <Tooltip
                contentStyle={{
                  backgroundColor: '#1e293b',
                  border: '1px solid #334155',
                  borderRadius: '0.5rem',
                }}
              />
              <Bar dataKey="count" fill="#3b82f6" />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Modals */}
      {/* All Anomalies Modal */}
      <DataTableModal
        isOpen={activeModal === 'alerts'}
        onClose={() => setActiveModal(null)}
        title="All Anomalies"
        columns={[
          { key: 'severity', label: 'Severity', render: (val) => (
            <span className={`px-2 py-1 rounded text-xs font-semibold ${getSeverityBadge(val)}`}>
              {val.toUpperCase()}
            </span>
          )},
          { key: 'title', label: 'Title' },
          { key: 'anomaly_type', label: 'Type' },
          { key: 'affected_user', label: 'User' },
          { key: 'affected_ip', label: 'IP' },
          { key: 'confidence_score', label: 'Confidence', render: (val) => `${(val * 100).toFixed(0)}%` },
          { key: 'detected_at', label: 'Detected', render: formatTimestamp },
        ]}
        fetchData={fetchAnomalies}
        expandable={true}
        renderExpandedRow={(row) => <LogEntryDetails logEntryId={row.log_entry_id} />}
      />

      {/* Critical Anomalies Modal */}
      <DataTableModal
        isOpen={activeModal === 'critical_alerts'}
        onClose={() => setActiveModal(null)}
        title="Critical & High Severity Anomalies"
        columns={[
          { key: 'severity', label: 'Severity', render: (val) => (
            <span className={`px-2 py-1 rounded text-xs font-semibold ${getSeverityBadge(val)}`}>
              {val.toUpperCase()}
            </span>
          )},
          { key: 'title', label: 'Title' },
          { key: 'description', label: 'Description' },
          { key: 'affected_user', label: 'User' },
          { key: 'affected_ip', label: 'IP' },
          { key: 'recommendation', label: 'Recommendation' },
        ]}
        fetchData={fetchCriticalAnomalies}
        expandable={true}
        renderExpandedRow={(row) => <LogEntryDetails logEntryId={row.log_entry_id} />}
      />

      {/* Log Volume Modal */}
      <DataTableModal
        isOpen={activeModal === 'log_volume'}
        onClose={() => setActiveModal(null)}
        title="All Log Entries"
        columns={[
          { key: 'timestamp', label: 'Timestamp', render: formatTimestamp },
          { key: 'username', label: 'User' },
          { key: 'source_ip', label: 'Source IP' },
          { key: 'destination_ip', label: 'Dest IP' },
          { key: 'url', label: 'URL', render: (val) => val ? val.substring(0, 50) + '...' : '-' },
          { key: 'action', label: 'Action' },
          { key: 'risk_score', label: 'Risk' },
        ]}
        fetchData={(page, perPage, search) => fetchLogEntries(page, perPage, search, 'all')}
      />

      {/* Source IPs Modal */}
      <DataTableModal
        isOpen={activeModal === 'source_ips'}
        onClose={() => setActiveModal(null)}
        title="Unique Source IPs"
        columns={[
          { key: 'ip_address', label: 'IP Address' },
          { key: 'request_count', label: 'Requests' },
          { key: 'last_seen', label: 'Last Seen', render: formatTimestamp },
        ]}
        fetchData={(page, perPage, search) => fetchIPs(page, perPage, search, 'source')}
      />

      {/* Destination IPs Modal */}
      <DataTableModal
        isOpen={activeModal === 'dest_ips'}
        onClose={() => setActiveModal(null)}
        title="Unique Destination IPs"
        columns={[
          { key: 'ip_address', label: 'IP Address' },
          { key: 'request_count', label: 'Requests' },
          { key: 'last_seen', label: 'Last Seen', render: formatTimestamp },
        ]}
        fetchData={(page, perPage, search) => fetchIPs(page, perPage, search, 'destination')}
      />

      {/* Users Modal */}
      <DataTableModal
        isOpen={activeModal === 'users'}
        onClose={() => setActiveModal(null)}
        title="Unique Users"
        columns={[
          { key: 'username', label: 'Username' },
          { key: 'request_count', label: 'Requests' },
          { key: 'last_seen', label: 'Last Seen', render: formatTimestamp },
        ]}
        fetchData={fetchUsers}
      />

      {/* Blocked Connections Modal */}
      <DataTableModal
        isOpen={activeModal === 'blocked'}
        onClose={() => setActiveModal(null)}
        title="Blocked Connections"
        columns={[
          { key: 'timestamp', label: 'Timestamp', render: formatTimestamp },
          { key: 'username', label: 'User' },
          { key: 'source_ip', label: 'Source IP' },
          { key: 'url', label: 'URL', render: (val) => val ? val.substring(0, 50) + '...' : '-' },
          { key: 'url_category', label: 'Category' },
          { key: 'risk_score', label: 'Risk' },
        ]}
        fetchData={(page, perPage, search) => fetchLogEntries(page, perPage, search, 'blocked')}
      />

      {/* Allowed Connections Modal */}
      <DataTableModal
        isOpen={activeModal === 'allowed'}
        onClose={() => setActiveModal(null)}
        title="Allowed Connections"
        columns={[
          { key: 'timestamp', label: 'Timestamp', render: formatTimestamp },
          { key: 'username', label: 'User' },
          { key: 'source_ip', label: 'Source IP' },
          { key: 'url', label: 'URL', render: (val) => val ? val.substring(0, 50) + '...' : '-' },
          { key: 'url_category', label: 'Category' },
        ]}
        fetchData={(page, perPage, search) => fetchLogEntries(page, perPage, search, 'allowed')}
      />

      {/* Threats Modal */}
      <DataTableModal
        isOpen={activeModal === 'threats'}
        onClose={() => setActiveModal(null)}
        title="Detected Threats"
        columns={[
          { key: 'timestamp', label: 'Timestamp', render: formatTimestamp },
          { key: 'username', label: 'User' },
          { key: 'source_ip', label: 'Source IP' },
          { key: 'threat_name', label: 'Threat' },
          { key: 'malware_type', label: 'Type' },
          { key: 'url', label: 'URL', render: (val) => val ? val.substring(0, 40) + '...' : '-' },
          { key: 'risk_score', label: 'Risk' },
        ]}
        fetchData={(page, perPage, search) => fetchLogEntries(page, perPage, search, 'threats')}
      />

      {/* Bypassed Traffic Modal */}
      <DataTableModal
        isOpen={activeModal === 'bypassed'}
        onClose={() => setActiveModal(null)}
        title="Bypassed Traffic"
        columns={[
          { key: 'timestamp', label: 'Timestamp', render: formatTimestamp },
          { key: 'username', label: 'User' },
          { key: 'source_ip', label: 'Source IP' },
          { key: 'destination_ip', label: 'Dest IP' },
          { key: 'url', label: 'URL', render: (val) => val ? val.substring(0, 50) + '...' : '-' },
          { key: 'url_category', label: 'Category' },
        ]}
        fetchData={(page, perPage, search) => fetchLogEntries(page, perPage, search, 'bypassed')}
      />
    </div>
  );
};

export default MetricsOverview;

