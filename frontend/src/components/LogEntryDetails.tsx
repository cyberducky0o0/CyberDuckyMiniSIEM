import React, { useState, useEffect } from 'react';
import { anomalyApi } from '../services/api';
import { Loader2 } from 'lucide-react';

interface LogEntryDetailsProps {
  logEntryId: string;
}

const LogEntryDetails: React.FC<LogEntryDetailsProps> = ({ logEntryId }) => {
  const [logEntry, setLogEntry] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    loadLogEntry();
  }, [logEntryId]);

  const loadLogEntry = async () => {
    try {
      setLoading(true);
      const data = await anomalyApi.getLogEntryForAnomaly(logEntryId);
      setLogEntry(data);
    } catch (err: any) {
      setError(err.response?.data?.error || 'Failed to load log entry');
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center py-8">
        <Loader2 className="h-6 w-6 animate-spin text-primary-400" />
        <span className="ml-2 text-gray-400">Loading log entry details...</span>
      </div>
    );
  }

  if (error) {
    return (
      <div className="text-center py-8 text-red-400">
        {error}
      </div>
    );
  }

  if (!logEntry) {
    return (
      <div className="text-center py-8 text-gray-400">
        No log entry found
      </div>
    );
  }

  const formatTimestamp = (timestamp: string) => {
    return new Date(timestamp).toLocaleString();
  };

  const renderField = (label: string, value: any) => {
    if (value === null || value === undefined || value === '') return null;
    
    return (
      <div className="mb-3">
        <span className="text-gray-400 text-sm font-semibold">{label}:</span>
        <span className="ml-2 text-white text-sm">{String(value)}</span>
      </div>
    );
  };

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
      {/* Core Information */}
      <div className="bg-slate-800 rounded-lg p-4 border border-slate-700">
        <h4 className="text-sm font-bold text-primary-400 mb-3 uppercase">Core Information</h4>
        {renderField('Timestamp', formatTimestamp(logEntry.timestamp))}
        {renderField('Record ID', logEntry.record_id)}
        {renderField('Username', logEntry.username)}
        {renderField('Action', logEntry.action)}
        {renderField('Risk Score', logEntry.risk_score)}
      </div>

      {/* Network Information */}
      <div className="bg-slate-800 rounded-lg p-4 border border-slate-700">
        <h4 className="text-sm font-bold text-primary-400 mb-3 uppercase">Network</h4>
        {renderField('Source IP', logEntry.source_ip)}
        {renderField('Source Port', logEntry.source_port)}
        {renderField('Dest IP', logEntry.destination_ip)}
        {renderField('Dest Port', logEntry.destination_port)}
        {renderField('Protocol', logEntry.app_protocol)}
      </div>

      {/* URL Information */}
      <div className="bg-slate-800 rounded-lg p-4 border border-slate-700">
        <h4 className="text-sm font-bold text-primary-400 mb-3 uppercase">URL & Category</h4>
        {renderField('URL', logEntry.url)}
        {renderField('Hostname', logEntry.hostname)}
        {renderField('URL Category', logEntry.url_category)}
        {renderField('URL Super Category', logEntry.url_super_category)}
        {renderField('URL Class', logEntry.url_class)}
      </div>

      {/* Threat Information */}
      {(logEntry.threat_name || logEntry.malware_type || logEntry.malware_class) && (
        <div className="bg-red-900/20 rounded-lg p-4 border border-red-700">
          <h4 className="text-sm font-bold text-red-400 mb-3 uppercase">Threat Details</h4>
          {renderField('Threat Name', logEntry.threat_name)}
          {renderField('Malware Type', logEntry.malware_type)}
          {renderField('Malware Class', logEntry.malware_class)}
          {renderField('Malware Category', logEntry.malware_category)}
        </div>
      )}

      {/* Application Information */}
      <div className="bg-slate-800 rounded-lg p-4 border border-slate-700">
        <h4 className="text-sm font-bold text-primary-400 mb-3 uppercase">Application</h4>
        {renderField('App Name', logEntry.app_name)}
        {renderField('App Class', logEntry.app_class)}
        {renderField('HTTP Method', logEntry.http_method)}
        {renderField('HTTP Status', logEntry.http_status_code)}
      </div>

      {/* Data Transfer */}
      <div className="bg-slate-800 rounded-lg p-4 border border-slate-700">
        <h4 className="text-sm font-bold text-primary-400 mb-3 uppercase">Data Transfer</h4>
        {renderField('Bytes Sent', logEntry.source_bytes ? `${logEntry.source_bytes.toLocaleString()} bytes` : null)}
        {renderField('Bytes Received', logEntry.destination_bytes ? `${logEntry.destination_bytes.toLocaleString()} bytes` : null)}
        {renderField('Req Header Size', logEntry.req_header_size)}
        {renderField('Resp Header Size', logEntry.resp_header_size)}
      </div>

      {/* Device Information */}
      {(logEntry.device_hostname || logEntry.device_owner) && (
        <div className="bg-slate-800 rounded-lg p-4 border border-slate-700">
          <h4 className="text-sm font-bold text-primary-400 mb-3 uppercase">Device</h4>
          {renderField('Device Hostname', logEntry.device_hostname)}
          {renderField('Device Owner', logEntry.device_owner)}
          {renderField('Role', logEntry.role)}
        </div>
      )}

      {/* Policy & Security */}
      <div className="bg-slate-800 rounded-lg p-4 border border-slate-700">
        <h4 className="text-sm font-bold text-primary-400 mb-3 uppercase">Policy & Security</h4>
        {renderField('Policy', logEntry.policy)}
        {renderField('Bypassed Traffic', logEntry.bypassed_traffic ? 'Yes' : 'No')}
        {renderField('Unscannable Type', logEntry.unscannable_type)}
        {renderField('DLP Engine', logEntry.dlp_engine)}
        {renderField('DLP Dictionary', logEntry.dlp_dictionary)}
      </div>

      {/* Additional Details */}
      {(logEntry.user_agent || logEntry.referer) && (
        <div className="bg-slate-800 rounded-lg p-4 border border-slate-700 md:col-span-2">
          <h4 className="text-sm font-bold text-primary-400 mb-3 uppercase">Additional Details</h4>
          {renderField('User Agent', logEntry.user_agent)}
          {renderField('Referer', logEntry.referer)}
          {renderField('Location', logEntry.location)}
          {renderField('Realm', logEntry.realm)}
        </div>
      )}
    </div>
  );
};

export default LogEntryDetails;

