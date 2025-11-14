import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { uploadApi } from '../services/api';
import { Upload, FileText, AlertCircle, CheckCircle } from 'lucide-react';
import NavigationBar from '../components/NavigationBar';

const UploadLogs: React.FC = () => {
  const navigate = useNavigate();
  const [isUploading, setIsUploading] = useState(false);
  const [uploadError, setUploadError] = useState('');
  const [uploadSuccess, setUploadSuccess] = useState('');
  const [selectedLogType, setSelectedLogType] = useState<string>('zscaler');

  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    setIsUploading(true);
    setUploadError('');
    setUploadSuccess('');

    try {
      const response = await uploadApi.uploadLogFile(file, selectedLogType);
      setUploadSuccess(`Successfully uploaded ${file.name}!`);

      // Navigate to analysis page after a short delay
      setTimeout(() => {
        navigate(`/analysis/${response.log_file.id}`);
      }, 1500);
    } catch (error: any) {
      setUploadError(error.response?.data?.error || 'Failed to upload file');
    } finally {
      setIsUploading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900">
      <NavigationBar />

      <main className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Header */}
        <div className="mb-8">
          <h1 className="text-3xl font-bold text-white mb-2">Upload Log Files</h1>
          <p className="text-gray-400">
            Upload Zscaler NSS Web Logs for analysis and threat detection
          </p>
        </div>

        {/* Upload Card */}
        <div className="card mb-6">
          <div className="mb-6">
            <h2 className="text-xl font-bold text-white mb-4">Select Log Type</h2>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <button
                onClick={() => setSelectedLogType('zscaler')}
                className={`p-4 rounded-lg border-2 transition-all ${
                  selectedLogType === 'zscaler'
                    ? 'border-primary-500 bg-primary-900/30'
                    : 'border-slate-600 hover:border-slate-500'
                }`}
              >
                <div className="text-center">
                  <FileText className="h-8 w-8 mx-auto mb-2 text-primary-400" />
                  <h3 className="font-medium text-white">Zscaler NSS</h3>
                  <p className="text-xs text-gray-400 mt-1">Web Proxy Logs</p>
                </div>
              </button>

              <button
                onClick={() => setSelectedLogType('apache')}
                className={`p-4 rounded-lg border-2 transition-all opacity-50 cursor-not-allowed ${
                  selectedLogType === 'apache'
                    ? 'border-primary-500 bg-primary-900/30'
                    : 'border-slate-600'
                }`}
                disabled
              >
                <div className="text-center">
                  <FileText className="h-8 w-8 mx-auto mb-2 text-gray-500" />
                  <h3 className="font-medium text-gray-400">Apache</h3>
                  <p className="text-xs text-gray-500 mt-1">Coming Soon</p>
                </div>
              </button>

              <button
                onClick={() => setSelectedLogType('nginx')}
                className={`p-4 rounded-lg border-2 transition-all opacity-50 cursor-not-allowed ${
                  selectedLogType === 'nginx'
                    ? 'border-primary-500 bg-primary-900/30'
                    : 'border-slate-600'
                }`}
                disabled
              >
                <div className="text-center">
                  <FileText className="h-8 w-8 mx-auto mb-2 text-gray-500" />
                  <h3 className="font-medium text-gray-400">Nginx</h3>
                  <p className="text-xs text-gray-500 mt-1">Coming Soon</p>
                </div>
              </button>
            </div>
          </div>

          {/* Upload Area */}
          <div className="border-2 border-dashed border-slate-600 rounded-lg p-8 text-center hover:border-primary-500 transition-colors">
            <Upload className="h-12 w-12 mx-auto mb-4 text-gray-400" />
            <h3 className="text-lg font-medium text-white mb-2">
              Drop your log file here or click to browse
            </h3>
            <p className="text-sm text-gray-400 mb-4">
              Supports CSV format (Zscaler NSS Web Logs)
            </p>
            <label className="inline-block">
              <input
                type="file"
                accept=".csv,.log,.txt"
                onChange={handleFileUpload}
                disabled={isUploading}
                className="hidden"
              />
              <span className="px-6 py-3 bg-primary-600 hover:bg-primary-700 text-white rounded-lg cursor-pointer inline-flex items-center space-x-2 transition-colors disabled:opacity-50">
                <Upload className="h-4 w-4" />
                <span>{isUploading ? 'Uploading...' : 'Select File'}</span>
              </span>
            </label>
          </div>

          {/* Status Messages */}
          {uploadError && (
            <div className="mt-4 p-4 bg-red-900/30 border border-red-700 rounded-lg flex items-start space-x-3">
              <AlertCircle className="h-5 w-5 text-red-400 flex-shrink-0 mt-0.5" />
              <div>
                <p className="text-red-200 font-medium">Upload Failed</p>
                <p className="text-red-300 text-sm mt-1">{uploadError}</p>
              </div>
            </div>
          )}

          {uploadSuccess && (
            <div className="mt-4 p-4 bg-green-900/30 border border-green-700 rounded-lg flex items-start space-x-3">
              <CheckCircle className="h-5 w-5 text-green-400 flex-shrink-0 mt-0.5" />
              <div>
                <p className="text-green-200 font-medium">Upload Successful</p>
                <p className="text-green-300 text-sm mt-1">{uploadSuccess}</p>
                <p className="text-green-400 text-xs mt-1">Redirecting to analysis...</p>
              </div>
            </div>
          )}
        </div>
      </main>
    </div>
  );
};

export default UploadLogs;

