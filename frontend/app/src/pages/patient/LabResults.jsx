import React, { useEffect, useMemo, useState } from 'react';
import { FileText, Calendar, Search, AlertCircle, CheckCircle, Clock } from 'lucide-react';
import Card from '../../components/common/Card';
import Badge from '../../components/common/Badge';
import { useAuth } from '../../contexts/AuthContext';
import api from '../../services/api';

const PatientLabResults = () => {
  const { user } = useAuth();
  const [patientId, setPatientId] = useState(null);
  const [results, setResults] = useState([]);
  const [searchTerm, setSearchTerm] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState(null);

  useEffect(() => {
    const fetchData = async () => {
      if (!user?.userId) {
        return;
      }
      setIsLoading(true);
      setError(null);
      try {
        const patient = await api.patients.getMe();
        if (!patient?.id) {
          throw new Error('Patient profile not found');
        }
        setPatientId(patient.id);
        const data = await api.labResults.getByPatient(patient.id);
        setResults(data || []);
      } catch (err) {
        setError('Failed to load lab results. Please refresh the page.');
      } finally {
        setIsLoading(false);
      }
    };

    fetchData();
  }, [user?.userId]);

  const filtered = useMemo(() => {
    const q = searchTerm.trim().toLowerCase();
    if (!q) return results;
    return results.filter((r) =>
      (r.testName || '').toLowerCase().includes(q) ||
      (r.testCategory || '').toLowerCase().includes(q) ||
      (r.orderedByName || '').toLowerCase().includes(q)
    );
  }, [results, searchTerm]);

  const getStatusType = (status) => {
    const s = (status || '').toUpperCase();
    if (s === 'COMPLETED') return 'green';
    if (s === 'PENDING') return 'yellow';
    if (s === 'CANCELLED') return 'red';
    return 'gray';
  };

  if (isLoading) {
    return <div className="p-6 text-center text-gray-500 dark:text-slate-400">Loading lab results...</div>;
  }

  return (
    <div className="space-y-4">
      <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-3">
        <div>
          <h2 className="text-lg font-semibold text-gray-800 dark:text-slate-100">Lab Results</h2>
          <p className="text-sm text-gray-500 dark:text-slate-400">Patient profile ID: {patientId || 'N/A'}</p>
        </div>
      </div>

      {error && (
        <Card className="p-3 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800">
          <p className="text-sm text-red-700 dark:text-red-300">{error}</p>
        </Card>
      )}

      <div className="relative">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-400" size={16} />
        <input
          type="text"
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          placeholder="Search test name, category, or ordered by..."
          className="w-full pl-9 pr-3 py-2 border border-gray-300 dark:border-slate-600 rounded-md bg-white dark:bg-slate-800 text-sm"
        />
      </div>

      <div className="space-y-3">
        {filtered.map((r) => (
          <Card key={r.testId} className="p-4">
            <div className="flex flex-col md:flex-row justify-between gap-3">
              <div className="space-y-1">
                <div className="flex items-center gap-2">
                  <FileText size={16} className="text-blue-500" />
                  <h3 className="text-sm font-semibold text-gray-900 dark:text-slate-100">{r.testName}</h3>
                  <Badge size="sm" type={getStatusType(r.status)}>{(r.status || 'UNKNOWN').toUpperCase()}</Badge>
                </div>
                <p className="text-xs text-gray-500 dark:text-slate-400">Category: {r.testCategory || 'N/A'}</p>
                <p className="text-xs text-gray-500 dark:text-slate-400">Ordered By: {r.orderedByName || 'N/A'}</p>
                <p className="text-xs text-gray-500 dark:text-slate-400">Result: {r.resultValue || 'Pending'} {r.unit || ''}</p>
                <p className="text-xs text-gray-500 dark:text-slate-400">Reference: {r.referenceRange || 'N/A'}</p>
              </div>
              <div className="text-xs text-gray-500 dark:text-slate-400 flex items-center gap-1">
                <Calendar size={14} />
                {r.orderedAt ? new Date(r.orderedAt).toLocaleString() : 'N/A'}
              </div>
            </div>
          </Card>
        ))}

        {filtered.length === 0 && (
          <Card className="p-6 text-center text-gray-500 dark:text-slate-400">
            <div className="flex items-center justify-center gap-2 mb-2">
              {results.length === 0 ? <Clock size={16} /> : <AlertCircle size={16} />}
              <span>{results.length === 0 ? 'No lab results found.' : 'No results match your search.'}</span>
            </div>
            {results.length > 0 && <CheckCircle size={16} className="mx-auto text-green-500" />}
          </Card>
        )}
      </div>
    </div>
  );
};

export default PatientLabResults;
