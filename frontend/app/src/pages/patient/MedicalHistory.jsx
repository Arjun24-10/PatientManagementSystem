import React, { useEffect, useState } from 'react';
import { FileText, Calendar, User, Stethoscope } from 'lucide-react';
import Card from '../../components/common/Card';
import { useAuth } from '../../contexts/AuthContext';
import api from '../../services/api';

const PatientMedicalHistory = () => {
  const { user } = useAuth();
  const [records, setRecords] = useState([]);
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
        const data = await api.medicalRecords.getByPatient(patient.id);
        setRecords(data || []);
      } catch (err) {
        setError('Failed to load medical history. Please refresh the page.');
      } finally {
        setIsLoading(false);
      }
    };

    fetchData();
  }, [user?.userId]);

  if (isLoading) {
    return <div className="p-6 text-center text-gray-500 dark:text-slate-400">Loading medical history...</div>;
  }

  return (
    <div className="space-y-4">
      <div>
        <h2 className="text-lg font-semibold text-gray-800 dark:text-slate-100">Medical History</h2>
        <p className="text-sm text-gray-500 dark:text-slate-400">Timeline of diagnoses and treatments</p>
      </div>

      {error && (
        <Card className="p-3 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800">
          <p className="text-sm text-red-700 dark:text-red-300">{error}</p>
        </Card>
      )}

      <div className="space-y-3">
        {records.map((r) => (
          <Card key={r.recordId} className="p-4">
            <div className="space-y-2">
              <div className="flex items-center gap-2">
                <Stethoscope size={16} className="text-blue-500" />
                <h3 className="text-sm font-semibold text-gray-900 dark:text-slate-100">{r.diagnosis || 'No diagnosis'}</h3>
              </div>
              <p className="text-sm text-gray-700 dark:text-slate-300">Symptoms: {r.symptoms || 'N/A'}</p>
              <p className="text-sm text-gray-700 dark:text-slate-300">Treatment: {r.treatmentProvided || 'N/A'}</p>
              <div className="flex flex-wrap gap-3 text-xs text-gray-500 dark:text-slate-400">
                <span className="flex items-center gap-1"><User size={14} /> {r.doctorName || 'N/A'}</span>
                <span className="flex items-center gap-1"><Calendar size={14} /> {r.recordDate ? new Date(r.recordDate).toLocaleString() : 'N/A'}</span>
              </div>
            </div>
          </Card>
        ))}

        {records.length === 0 && (
          <Card className="p-6 text-center text-gray-500 dark:text-slate-400">
            <FileText size={16} className="mx-auto mb-2" />
            No medical history records found.
          </Card>
        )}
      </div>
    </div>
  );
};

export default PatientMedicalHistory;
