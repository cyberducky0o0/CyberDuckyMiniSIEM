import React from 'react';
import { useNavigate } from 'react-router-dom';
import { X, FileText, AlertTriangle, Shield } from 'lucide-react';

interface AllFilesModalProps {
  isOpen: boolean;
  onClose: () => void;
  files: any[];
  title: string;
  focusColumn?: 'anomalies' | 'threats';
}

const AllFilesModal: React.FC<AllFilesModalProps> = ({ 
  isOpen, 
  onClose, 
  files, 
  title,
  focusColumn = 'anomalies'
}) => {
  const navigate = useNavigate();

  if (!isOpen) return null;

  const handleFileClick = (fileId: string) => {
    navigate(`/analysis/${fileId}`);
    onClose();
  };

  return (
    <div className="fixed inset-0 z-50 overflow-y-auto">
      {/* Backdrop */}
      <div 
        className="fixed inset-0 bg-black bg-opacity-75 transition-opacity"
        onClick={onClose}
      ></div>

      {/* Modal */}
      <div className="flex min-h-screen items-center justify-center p-4">
        <div className="relative bg-slate-800 rounded-lg shadow-xl max-w-6xl w-full max-h-[90vh] overflow-hidden">
          {/* Header */}
          <div className="flex items-center justify-between p-6 border-b border-slate-700">
            <div className="flex items-center space-x-3">
              {focusColumn === 'anomalies' ? (
                <div className="bg-red-900/50 p-2 rounded-lg">
                  <AlertTriangle className="h-6 w-6 text-red-400" />
                </div>
              ) : (
                <div className="bg-red-900/50 p-2 rounded-lg">
                  <Shield className="h-6 w-6 text-red-400" />
                </div>
              )}
              <div>
                <h2 className="text-xl font-bold text-white">{title}</h2>
                <p className="text-sm text-gray-400">Click any row to view detailed analysis</p>
              </div>
            </div>
            <button
              onClick={onClose}
              className="text-gray-400 hover:text-white transition-colors"
            >
              <X className="h-6 w-6" />
            </button>
          </div>

          {/* Table */}
          <div className="overflow-y-auto max-h-[calc(90vh-120px)]">
            <table className="w-full">
              <thead className="bg-slate-900 sticky top-0">
                <tr className="border-b border-slate-700">
                  <th className="text-left py-3 px-4 text-xs font-medium text-gray-400">
                    Filename
                  </th>
                  <th className="text-left py-3 px-4 text-xs font-medium text-gray-400">
                    Status
                  </th>
                  <th className="text-right py-3 px-4 text-xs font-medium text-gray-400">
                    Total Entries
                  </th>
                  <th className="text-right py-3 px-4 text-xs font-medium text-gray-400">
                    <div className="flex items-center justify-end space-x-1">
                      <AlertTriangle className="h-3 w-3" />
                      <span>Anomalies</span>
                    </div>
                  </th>
                  <th className="text-right py-3 px-4 text-xs font-medium text-gray-400">
                    Critical
                  </th>
                  <th className="text-right py-3 px-4 text-xs font-medium text-gray-400">
                    High
                  </th>
                  <th className="text-right py-3 px-4 text-xs font-medium text-gray-400">
                    Avg Risk
                  </th>
                  <th className="text-left py-3 px-4 text-xs font-medium text-gray-400">
                    Uploaded
                  </th>
                </tr>
              </thead>
              <tbody>
                {files.length === 0 ? (
                  <tr>
                    <td colSpan={8} className="py-12 text-center text-gray-400">
                      No log files found
                    </td>
                  </tr>
                ) : (
                  files.map((file: any) => (
                    <tr
                      key={file.id}
                      className="border-b border-slate-700/50 cursor-pointer hover:bg-slate-700/30 transition-colors"
                      onClick={() => handleFileClick(file.id)}
                      title={`Click to view analysis for ${file.filename}`}
                    >
                      <td className="py-3 px-4 text-sm text-white">
                        <div className="flex items-center space-x-2">
                          <FileText className="h-4 w-4 text-blue-400 flex-shrink-0" />
                          <span className="font-medium truncate max-w-xs">{file.filename}</span>
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
                        <span className={`font-bold ${focusColumn === 'anomalies' ? 'text-red-400' : 'text-gray-300'}`}>
                          {file.anomaly_count || 0}
                        </span>
                      </td>
                      <td className="py-3 px-4 text-sm text-right">
                        <span className="text-red-500 font-medium">
                          {file.critical_count || 0}
                        </span>
                      </td>
                      <td className="py-3 px-4 text-sm text-right">
                        <span className="text-orange-400 font-medium">
                          {file.high_count || 0}
                        </span>
                      </td>
                      <td className="py-3 px-4 text-sm text-right">
                        <span
                          className={`px-2 py-1 rounded text-xs font-medium ${
                            (file.avg_risk_score || 0) >= 70
                              ? 'bg-red-900 text-red-200'
                              : (file.avg_risk_score || 0) >= 40
                              ? 'bg-orange-900 text-orange-200'
                              : 'bg-yellow-900 text-yellow-200'
                          }`}
                        >
                          {file.avg_risk_score?.toFixed(1) || '0.0'}
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
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
};

export default AllFilesModal;

