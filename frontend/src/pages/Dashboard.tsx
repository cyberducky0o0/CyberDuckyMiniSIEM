import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { uploadApi } from '../services/api';
import { AlertCircle, CheckCircle, Clock, RefreshCw, Trash2, FileText } from 'lucide-react';
import NavigationBar from '../components/NavigationBar';
import type { LogFile } from '../types';

const Dashboard: React.FC = () => {
  const navigate = useNavigate();
  const { user, logout } = useAuth();
  const [logFiles, setLogFiles] = useState<LogFile[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [isUploading, setIsUploading] = useState(false);
  const [uploadError, setUploadError] = useState('');
  const [uploadSuccess, setUploadSuccess] = useState('');
  const [reprocessingId, setReprocessingId] = useState<string | null>(null);
  const [deletingId, setDeletingId] = useState<string | null>(null);
  const [selectedLogType, setSelectedLogType] = useState<string>('zscaler');

  useEffect(() => {
    loadLogFiles();
  }, []);

  const loadLogFiles = async () => {
    try {
      const files = await uploadApi.getLogFiles();
      setLogFiles(files);
    } catch (error) {
      console.error('Failed to load log files:', error);
    } finally {
      setIsLoading(false);
    }
  };

  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    setIsUploading(true);
    setUploadError('');
    setUploadSuccess('');

    try {
      const response = await uploadApi.uploadLogFile(file, selectedLogType);
      setUploadSuccess(`Successfully uploaded ${file.name}!`);
      
      // Reload log files
      await loadLogFiles();
      
      // Navigate to analysis page after a short delay
      setTimeout(() => {
        navigate(`/analysis/${response.log_file.id}`);
      }, 1500);
    } catch (error: any) {
      setUploadError(error.response?.data?.error || 'Failed to upload file. Please try again.');
    } finally {
      setIsUploading(false);
      // Reset file input
      e.target.value = '';
    }
  };

  const handleLogout = () => {
    logout();
    navigate('/login');
  };

  const handleReprocess = async (fileId: string) => {
    setReprocessingId(fileId);
    setUploadError('');
    setUploadSuccess('');

    try {
      await uploadApi.reprocessLogFile(fileId);
      setUploadSuccess('File reprocessed successfully!');

      // Reload log files to show updated stats
      await loadLogFiles();
    } catch (error: any) {
      setUploadError(error.response?.data?.error || 'Failed to reprocess file. Please try again.');
    } finally {
      setReprocessingId(null);
    }
  };

  const handleDelete = async (fileId: string, filename: string) => {
    if (!confirm(`Are you sure you want to delete "${filename}"? This action cannot be undone.`)) {
      return;
    }

    setDeletingId(fileId);
    setUploadError('');
    setUploadSuccess('');

    try {
      await uploadApi.deleteLogFile(fileId);
      setUploadSuccess(`Successfully deleted ${filename}!`);

      // Reload log files
      await loadLogFiles();
    } catch (error: any) {
      setUploadError(error.response?.data?.error || 'Failed to delete file. Please try again.');
    } finally {
      setDeletingId(null);
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'completed':
        return <CheckCircle className="h-5 w-5 text-success-400" />;
      case 'processing':
        return <Clock className="h-5 w-5 text-warning-400 animate-spin" />;
      case 'failed':
        return <AlertCircle className="h-5 w-5 text-danger-400" />;
      default:
        return <Clock className="h-5 w-5 text-gray-400" />;
    }
  };

  const getStatusBadge = (status: string) => {
    const badges = {
      completed: 'badge-info',
      processing: 'badge-medium',
      failed: 'badge-critical',
      pending: 'badge-low',
    };
    return badges[status as keyof typeof badges] || 'badge';
  };

  const getLogTypeBadge = (logType: string) => {
    const types: Record<string, { label: string; color: string }> = {
      zscaler: { label: 'Zscaler', color: 'bg-blue-900 text-blue-200 border-blue-700' },
      apache: { label: 'Apache', color: 'bg-purple-900 text-purple-200 border-purple-700' },
      custom: { label: 'Custom', color: 'bg-gray-900 text-gray-200 border-gray-700' },
    };
    const type = types[logType] || { label: logType, color: 'bg-gray-900 text-gray-200 border-gray-700' };
    return (
      <span className={`px-2 py-1 text-xs font-medium rounded border ${type.color}`}>
        {type.label}
      </span>
    );
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900">
      <NavigationBar />

      {/* Main Content */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Page Header */}
        <div className="mb-8">
          <h1 className="text-3xl font-bold text-white mb-2">Recently Uploaded Logs</h1>
          <p className="text-gray-400">
            View and manage your uploaded log files
          </p>
        </div>

        {/* Log Files List */}
        <div className="card">
          <div className="flex items-center justify-between mb-6">
            <h2 className="text-xl font-bold text-white">Recent Log Files</h2>
            <button
              onClick={loadLogFiles}
              disabled={isLoading}
              className="flex items-center space-x-2 px-4 py-2 bg-slate-700 hover:bg-slate-600 text-white rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
              title="Refresh file list"
            >
              <RefreshCw className={`h-4 w-4 ${isLoading ? 'animate-spin' : ''}`} />
              <span>Refresh</span>
            </button>
          </div>

          {isLoading ? (
            <div className="text-center py-12">
              <div className="inline-block animate-spin rounded-full h-8 w-8 border-b-2 border-primary-500"></div>
              <p className="mt-4 text-gray-400">Loading log files...</p>
            </div>
          ) : logFiles.length === 0 ? (
            <div className="text-center py-12">
              <FileText className="h-16 w-16 text-gray-600 mx-auto mb-4" />
              <p className="text-gray-400">No log files uploaded yet</p>
              <p className="text-sm text-gray-500 mt-2">Upload your first Zscaler log file to get started</p>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="border-b border-slate-700">
                    <th className="text-left py-3 px-4 text-sm font-medium text-gray-400">Filename</th>
                    <th className="text-left py-3 px-4 text-sm font-medium text-gray-400">Type</th>
                    <th className="text-left py-3 px-4 text-sm font-medium text-gray-400">Status</th>
                    <th className="text-left py-3 px-4 text-sm font-medium text-gray-400">Entries</th>
                    <th className="text-left py-3 px-4 text-sm font-medium text-gray-400">Uploaded</th>
                    <th className="text-left py-3 px-4 text-sm font-medium text-gray-400">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {logFiles.map((file) => (
                    <tr
                      key={file.id}
                      className="border-b border-slate-700 hover:bg-slate-700/50 transition-colors"
                    >
                      <td className="py-4 px-4">
                        <div className="flex items-center space-x-3">
                          <FileText className="h-5 w-5 text-primary-400" />
                          <span className="text-white font-medium">{file.filename}</span>
                        </div>
                      </td>
                      <td className="py-4 px-4">
                        {getLogTypeBadge(file.log_type)}
                      </td>
                      <td className="py-4 px-4">
                        <div className="flex items-center space-x-2">
                          {getStatusIcon(file.upload_status)}
                          <span className={`${getStatusBadge(file.upload_status)}`}>
                            {file.upload_status}
                          </span>
                        </div>
                      </td>
                      <td className="py-4 px-4 text-gray-300">{file.parsed_entries}</td>
                      <td className="py-4 px-4 text-gray-300">
                        {new Date(file.uploaded_at).toLocaleString()}
                      </td>
                      <td className="py-4 px-4">
                        <div className="flex items-center space-x-2">
                          {file.upload_status === 'completed' && (
                            <button
                              onClick={() => navigate(`/analysis/${file.id}`)}
                              className="text-primary-400 hover:text-primary-300 font-medium text-sm whitespace-nowrap"
                            >
                              View Analysis →
                            </button>
                          )}

                          {(file.upload_status === 'completed' || file.upload_status === 'failed') && (
                            <>
                              <button
                                onClick={() => handleReprocess(file.id)}
                                disabled={reprocessingId === file.id || deletingId === file.id}
                                className="flex items-center space-x-1 text-warning-400 hover:text-warning-300 font-medium text-sm disabled:opacity-50 disabled:cursor-not-allowed whitespace-nowrap"
                                title="Reprocess this file"
                              >
                                <RefreshCw className={`h-3 w-3 ${reprocessingId === file.id ? 'animate-spin' : ''}`} />
                                <span className="hidden sm:inline">
                                  {reprocessingId === file.id ? 'Processing...' : file.upload_status === 'failed' ? 'Retry' : 'Reprocess'}
                                </span>
                              </button>

                              <button
                                onClick={() => handleDelete(file.id, file.filename)}
                                disabled={deletingId === file.id || reprocessingId === file.id}
                                className="flex items-center space-x-1 text-danger-400 hover:text-danger-300 font-medium text-sm disabled:opacity-50 disabled:cursor-not-allowed whitespace-nowrap"
                                title="Delete this file"
                              >
                                <Trash2 className="h-3 w-3" />
                                <span className="hidden sm:inline">
                                  {deletingId === file.id ? 'Deleting...' : 'Delete'}
                                </span>
                              </button>
                            </>
                          )}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </main>
    </div>
  );
};

export default Dashboard;

