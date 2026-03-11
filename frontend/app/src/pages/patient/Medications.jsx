import React, { useEffect, useMemo, useState } from 'react';
import { Pill, AlertCircle } from 'lucide-react';
import Card from '../../components/common/Card';
import Badge from '../../components/common/Badge';
import { useAuth } from '../../contexts/AuthContext';
import api from '../../services/api';

const PatientMedications = () => {
  const { user } = useAuth();
  const [prescriptions, setPrescriptions] = useState([]);
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
        const data = await api.prescriptions.getByPatient(patient.id);
        setPrescriptions(data || []);
      } catch (err) {
        setError('Failed to load medications. Please refresh the page.');
      } finally {
        setIsLoading(false);
      }
    };

    fetchData();
  }, [user?.userId]);

  const active = useMemo(() => prescriptions.filter((p) => (p.status || '').toUpperCase() === 'ACTIVE'), [prescriptions]);

  if (isLoading) {
    return <div className="p-6 text-center text-gray-500 dark:text-slate-400">Loading medications...</div>;
  }

  return (
    <div className="space-y-4">
      <div>
        <h2 className="text-lg font-semibold text-gray-800 dark:text-slate-100">Medications</h2>
        <p className="text-sm text-gray-500 dark:text-slate-400">Current and past prescriptions</p>
      </div>

      {error && (
        <Card className="p-3 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800">
          <p className="text-sm text-red-700 dark:text-red-300">{error}</p>
        </Card>
      )}

      <div className="space-y-3">
        {active.map((rx) => (
          <Card key={rx.prescriptionId} className="p-4">
            <div className="flex items-start gap-3">
              <Pill size={16} className="text-blue-500 mt-0.5" />
              <div className="space-y-1">
                <div className="flex items-center gap-2">
                  <h3 className="text-sm font-semibold text-gray-900 dark:text-slate-100">{rx.medicationName}</h3>
                  <Badge size="sm" type="green">ACTIVE</Badge>
                  {(rx.refillsRemaining ?? 0) <= 1 && <AlertCircle size={14} className="text-red-500" />}
                </div>
                <p className="text-sm text-gray-600 dark:text-slate-300">{rx.dosage} • {rx.frequency}</p>
                <p className="text-xs text-gray-500 dark:text-slate-400">Doctor: {rx.doctorName || 'N/A'}</p>
                <p className="text-xs text-gray-500 dark:text-slate-400">Refills remaining: {rx.refillsRemaining ?? 0}</p>
              </div>
            </div>
          </Card>
        ))}

        {active.length === 0 && (
          <Card className="p-6 text-center text-gray-500 dark:text-slate-400">No active medications.</Card>
        )}
      </div>
    </div>
  );
};

export default PatientMedications;
