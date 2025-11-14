import React, { useState, useEffect } from 'react';
import { X, Search, ChevronLeft, ChevronRight, ChevronDown, ChevronUp } from 'lucide-react';

interface Column {
  key: string;
  label: string;
  render?: (value: any, row: any) => React.ReactNode;
}

interface DataTableModalProps {
  isOpen: boolean;
  onClose: () => void;
  title: string;
  columns: Column[];
  fetchData: (page: number, perPage: number, search: string) => Promise<{
    data: any[];
    total: number;
    page: number;
    per_page: number;
    total_pages: number;
  }>;
  emptyMessage?: string;
  expandable?: boolean;
  renderExpandedRow?: (row: any) => React.ReactNode;
}

const DataTableModal: React.FC<DataTableModalProps> = ({
  isOpen,
  onClose,
  title,
  columns,
  fetchData,
  emptyMessage = 'No data found',
  expandable = false,
  renderExpandedRow,
}) => {
  const [data, setData] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);
  const [search, setSearch] = useState('');
  const [page, setPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const [total, setTotal] = useState(0);
  const [expandedRows, setExpandedRows] = useState<Set<string>>(new Set());
  const perPage = 10;

  useEffect(() => {
    if (isOpen) {
      loadData();
    }
  }, [isOpen, page, search]);

  const loadData = async () => {
    setLoading(true);
    try {
      const result = await fetchData(page, perPage, search);
      setData(result.data);
      setTotal(result.total);
      setTotalPages(result.total_pages);
    } catch (error) {
      console.error('Failed to load data:', error);
      setData([]);
    } finally {
      setLoading(false);
    }
  };

  const handleSearchChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setSearch(e.target.value);
    setPage(1); // Reset to first page on search
  };

  const handlePrevPage = () => {
    if (page > 1) setPage(page - 1);
  };

  const handleNextPage = () => {
    if (page < totalPages) setPage(page + 1);
  };

  const toggleRow = (rowId: string) => {
    const newExpanded = new Set(expandedRows);
    if (newExpanded.has(rowId)) {
      newExpanded.delete(rowId);
    } else {
      newExpanded.add(rowId);
    }
    setExpandedRows(newExpanded);
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm">
      <div className="bg-slate-800 rounded-lg shadow-2xl w-full max-w-6xl max-h-[90vh] flex flex-col border border-slate-700">
        {/* Header */}
        <div className="flex items-center justify-between p-6 border-b border-slate-700">
          <h2 className="text-2xl font-bold text-white">{title}</h2>
          <button
            onClick={onClose}
            className="p-2 hover:bg-slate-700 rounded-lg transition-colors"
          >
            <X className="h-6 w-6 text-gray-400" />
          </button>
        </div>

        {/* Search Bar */}
        <div className="p-4 border-b border-slate-700">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-5 w-5 text-gray-400" />
            <input
              type="text"
              placeholder="Search..."
              value={search}
              onChange={handleSearchChange}
              className="w-full pl-10 pr-4 py-2 bg-slate-900 border border-slate-600 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-primary-500"
            />
          </div>
        </div>

        {/* Table */}
        <div className="flex-1 overflow-auto p-4">
          {loading ? (
            <div className="flex items-center justify-center py-12">
              <div className="inline-block animate-spin rounded-full h-8 w-8 border-b-2 border-primary-500"></div>
            </div>
          ) : data.length === 0 ? (
            <div className="text-center py-12 text-gray-400">{emptyMessage}</div>
          ) : (
            <table className="w-full">
              <thead>
                <tr className="border-b border-slate-700">
                  {expandable && <th className="w-10"></th>}
                  {columns.map((column) => (
                    <th
                      key={column.key}
                      className="text-left py-3 px-4 text-sm font-semibold text-gray-300 uppercase tracking-wider"
                    >
                      {column.label}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {data.map((row, index) => {
                  const rowId = row.id || `row-${index}`;
                  const isExpanded = expandedRows.has(rowId);

                  return (
                    <React.Fragment key={rowId}>
                      <tr className="border-b border-slate-700/50 hover:bg-slate-700/30 transition-colors">
                        {expandable && (
                          <td className="py-3 px-2">
                            <button
                              onClick={() => toggleRow(rowId)}
                              className="text-gray-400 hover:text-white transition-colors"
                            >
                              {isExpanded ? (
                                <ChevronUp className="h-4 w-4" />
                              ) : (
                                <ChevronDown className="h-4 w-4" />
                              )}
                            </button>
                          </td>
                        )}
                        {columns.map((column) => (
                          <td key={column.key} className="py-3 px-4 text-sm text-gray-300">
                            {column.render
                              ? column.render(row[column.key], row)
                              : row[column.key] || '-'}
                          </td>
                        ))}
                      </tr>
                      {expandable && isExpanded && renderExpandedRow && (
                        <tr className="bg-slate-900/50">
                          <td colSpan={columns.length + 1} className="py-4 px-6">
                            {renderExpandedRow(row)}
                          </td>
                        </tr>
                      )}
                    </React.Fragment>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>

        {/* Pagination */}
        <div className="flex items-center justify-between p-4 border-t border-slate-700">
          <div className="text-sm text-gray-400">
            Showing {data.length > 0 ? (page - 1) * perPage + 1 : 0} to{' '}
            {Math.min(page * perPage, total)} of {total} results
          </div>
          <div className="flex items-center space-x-2">
            <button
              onClick={handlePrevPage}
              disabled={page === 1}
              className="p-2 rounded-lg bg-slate-700 hover:bg-slate-600 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
            >
              <ChevronLeft className="h-5 w-5 text-white" />
            </button>
            <span className="text-sm text-gray-300">
              Page {page} of {totalPages}
            </span>
            <button
              onClick={handleNextPage}
              disabled={page === totalPages}
              className="p-2 rounded-lg bg-slate-700 hover:bg-slate-600 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
            >
              <ChevronRight className="h-5 w-5 text-white" />
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default DataTableModal;

