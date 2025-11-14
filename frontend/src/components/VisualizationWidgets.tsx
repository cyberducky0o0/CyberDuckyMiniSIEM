import React from 'react';
import {
  LineChart,
  Line,
  BarChart,
  Bar,
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
  ReferenceLine,
} from 'recharts';
import { TrendingUp, Activity, Clock, AlertTriangle } from 'lucide-react';

interface RiskTrendlineProps {
  data: {
    timestamps: string[];
    risk_scores: number[];
    moving_avg?: number[];
    ewma?: number[];
    upper_band?: number[];
    lower_band?: number[];
    mean?: number;
    std_dev?: number;
  };
}

export const RiskTrendlineWidget: React.FC<RiskTrendlineProps> = ({ data }) => {
  if (!data || !data.timestamps || !Array.isArray(data.timestamps) || data.timestamps.length === 0) {
    return (
      <div className="card">
        <h3 className="text-lg font-bold text-white mb-4 flex items-center">
          <TrendingUp className="h-5 w-5 mr-2 text-primary-400" />
          Risk Score Trendline
        </h3>
        <div className="text-center py-8 text-gray-400">No data available</div>
      </div>
    );
  }

  // Transform data for recharts with null safety
  const chartData = data.timestamps.map((timestamp, index) => ({
    time: timestamp ? new Date(timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : '',
    risk: data.risk_scores?.[index] ?? 0,
    ma: data.moving_avg?.[index] ?? null,
    ewma: data.ewma?.[index] ?? null,
    upper: data.upper_band?.[index],
    lower: data.lower_band?.[index],
  }));

  return (
    <div className="card">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-lg font-bold text-white flex items-center">
          <TrendingUp className="h-5 w-5 mr-2 text-primary-400" />
          Risk Score Trendline
        </h3>
        <div className="text-sm text-gray-400">
          Mean: {data.mean?.toFixed(2)} | Std Dev: {data.std_dev?.toFixed(2)}
        </div>
      </div>
      <ResponsiveContainer width="100%" height={300}>
        <LineChart data={chartData}>
          <CartesianGrid strokeDasharray="3 3" stroke="#475569" />
          <XAxis
            dataKey="time"
            stroke="#94a3b8"
            tick={{ fontSize: 12 }}
            interval="preserveStartEnd"
          />
          <YAxis stroke="#94a3b8" />
          <Tooltip
            contentStyle={{
              backgroundColor: '#1e293b',
              border: '1px solid #475569',
              borderRadius: '0.5rem',
            }}
          />
          <Legend />
          {data.upper_band && (
            <Line
              type="monotone"
              dataKey="upper"
              stroke="#ef4444"
              strokeDasharray="5 5"
              dot={false}
              name="Upper Band"
            />
          )}
          {data.lower_band && (
            <Line
              type="monotone"
              dataKey="lower"
              stroke="#22c55e"
              strokeDasharray="5 5"
              dot={false}
              name="Lower Band"
            />
          )}
          <Line
            type="monotone"
            dataKey="risk"
            stroke="#0ea5e9"
            strokeWidth={2}
            dot={{ r: 3 }}
            name="Risk Score"
          />
          {data.moving_avg && (
            <Line
              type="monotone"
              dataKey="ma"
              stroke="#f59e0b"
              strokeWidth={2}
              dot={false}
              name="Moving Avg"
            />
          )}
          {data.ewma && (
            <Line
              type="monotone"
              dataKey="ewma"
              stroke="#8b5cf6"
              strokeWidth={2}
              dot={false}
              name="EWMA"
            />
          )}
          {data.mean && <ReferenceLine y={data.mean} stroke="#64748b" strokeDasharray="3 3" />}
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
};

interface EventTimelineProps {
  data: {
    time_buckets: string[];
    event_counts: number[];
    anomaly_counts?: number[];
    bucket_size?: string;
  };
}

export const EventTimelineWidget: React.FC<EventTimelineProps> = ({ data }) => {
  if (!data || !data.time_buckets || !Array.isArray(data.time_buckets) || data.time_buckets.length === 0) {
    return (
      <div className="card">
        <h3 className="text-lg font-bold text-white mb-4 flex items-center">
          <Clock className="h-5 w-5 mr-2 text-primary-400" />
          Event Timeline
        </h3>
        <div className="text-center py-8 text-gray-400">No data available</div>
      </div>
    );
  }

  // Transform data for recharts with null safety
  const chartData = data.time_buckets.map((bucket, index) => ({
    time: bucket ? new Date(bucket).toLocaleString([], {
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    }) : '',
    events: data.event_counts?.[index] ?? 0,
    anomalies: data.anomaly_counts?.[index] ?? 0,
  }));

  return (
    <div className="card">
      <h3 className="text-lg font-bold text-white mb-4 flex items-center">
        <Clock className="h-5 w-5 mr-2 text-primary-400" />
        Event Timeline ({data.bucket_size || 'hour'})
      </h3>
      <ResponsiveContainer width="100%" height={300}>
        <BarChart data={chartData}>
          <CartesianGrid strokeDasharray="3 3" stroke="#475569" />
          <XAxis dataKey="time" stroke="#94a3b8" tick={{ fontSize: 12 }} angle={-45} textAnchor="end" height={100} />
          <YAxis stroke="#94a3b8" />
          <Tooltip
            contentStyle={{
              backgroundColor: '#1e293b',
              border: '1px solid #475569',
              borderRadius: '0.5rem',
            }}
          />
          <Legend />
          <Bar dataKey="events" fill="#0ea5e9" name="Total Events" />
          {data.anomaly_counts && <Bar dataKey="anomalies" fill="#ef4444" name="Anomalies" />}
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
};

interface AnomalyTimeSeriesProps {
  data: {
    time_series: Array<{
      time_bucket: string;
      total_anomalies: number;
      critical: number;
      high: number;
      medium: number;
      low: number;
    }>;
  };
}

export const AnomalyTimeSeriesWidget: React.FC<AnomalyTimeSeriesProps> = ({ data }) => {
  if (!data || !data.time_series || !Array.isArray(data.time_series) || data.time_series.length === 0) {
    return (
      <div className="card">
        <h3 className="text-lg font-bold text-white mb-4 flex items-center">
          <AlertTriangle className="h-5 w-5 mr-2 text-warning-400" />
          Anomaly Time Series
        </h3>
        <div className="text-center py-8 text-gray-400">No anomalies detected</div>
      </div>
    );
  }

  // Transform data for recharts with null safety
  const chartData = data.time_series.map((item) => ({
    time: item?.time_bucket ? new Date(item.time_bucket).toLocaleString([], {
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
    }) : '',
    total: item?.total_anomalies ?? 0,
    critical: item?.critical ?? 0,
    high: item?.high ?? 0,
    medium: item?.medium ?? 0,
    low: item?.low ?? 0,
  }));

  return (
    <div className="card">
      <h3 className="text-lg font-bold text-white mb-4 flex items-center">
        <AlertTriangle className="h-5 w-5 mr-2 text-warning-400" />
        Anomaly Time Series
      </h3>
      <ResponsiveContainer width="100%" height={300}>
        <AreaChart data={chartData}>
          <CartesianGrid strokeDasharray="3 3" stroke="#475569" />
          <XAxis dataKey="time" stroke="#94a3b8" tick={{ fontSize: 12 }} angle={-45} textAnchor="end" height={100} />
          <YAxis stroke="#94a3b8" />
          <Tooltip
            contentStyle={{
              backgroundColor: '#1e293b',
              border: '1px solid #475569',
              borderRadius: '0.5rem',
            }}
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
  );
};

interface RequestsPerMinuteProps {
  data: {
    timestamps: string[];
    request_counts: number[];
    group_by?: string;
  };
}

export const RequestsPerMinuteWidget: React.FC<RequestsPerMinuteProps> = ({ data }) => {
  if (!data || !data.timestamps || !Array.isArray(data.timestamps) || data.timestamps.length === 0) {
    return (
      <div className="card">
        <h3 className="text-lg font-bold text-white mb-4 flex items-center">
          <Activity className="h-5 w-5 mr-2 text-primary-400" />
          Requests Per Minute
        </h3>
        <div className="text-center py-8 text-gray-400">No data available</div>
      </div>
    );
  }

  // Transform data for recharts with null safety
  const chartData = data.timestamps.map((timestamp, index) => ({
    time: timestamp ? new Date(timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : '',
    requests: data.request_counts?.[index] ?? 0,
  }));

  // Calculate average
  const avgRequests = data.request_counts.reduce((a, b) => a + b, 0) / data.request_counts.length;
  const maxRequests = Math.max(...data.request_counts);

  return (
    <div className="card">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-lg font-bold text-white flex items-center">
          <Activity className="h-5 w-5 mr-2 text-primary-400" />
          Requests Per Minute
        </h3>
        <div className="text-sm text-gray-400">
          Avg: {avgRequests.toFixed(1)} | Max: {maxRequests}
        </div>
      </div>
      <ResponsiveContainer width="100%" height={300}>
        <AreaChart data={chartData}>
          <CartesianGrid strokeDasharray="3 3" stroke="#475569" />
          <XAxis
            dataKey="time"
            stroke="#94a3b8"
            tick={{ fontSize: 12 }}
            interval="preserveStartEnd"
          />
          <YAxis stroke="#94a3b8" />
          <Tooltip
            contentStyle={{
              backgroundColor: '#1e293b',
              border: '1px solid #475569',
              borderRadius: '0.5rem',
            }}
          />
          <Area
            type="monotone"
            dataKey="requests"
            stroke="#0ea5e9"
            fill="#0ea5e9"
            fillOpacity={0.6}
            name="Requests"
          />
          <ReferenceLine y={avgRequests} stroke="#f59e0b" strokeDasharray="3 3" label="Avg" />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
};

