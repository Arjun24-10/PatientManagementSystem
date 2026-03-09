import React, { useEffect, useState } from 'react';
import { User, Mail, Phone } from 'lucide-react';
import Card from '../../components/common/Card';
import { useAuth } from '../../contexts/AuthContext';
import api from '../../services/api';

const PatientProfile = () => {
  const { user } = useAuth();
  const [profile, setProfile] = useState(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState(null);

  useEffect(() => {
    const fetchProfile = async () => {
      if (!user?.userId) {
        return;
      }
      setIsLoading(true);
      setError(null);
      try {
        const data = await api.patients.getMe();
        setProfile(data);
      } catch (err) {
        setError('Failed to load profile. Please refresh the page.');
      } finally {
        setIsLoading(false);
      }
    };

    fetchProfile();
  }, [user?.userId]);

  if (isLoading) {
    return <div className="p-6 text-center text-gray-500 dark:text-slate-400">Loading profile...</div>;
  }

  const fullName = profile ? `${profile.firstName || ''} ${profile.lastName || ''}`.trim() : (user?.fullName || user?.email || 'Patient');

  return (
    <div className="space-y-4">
      <h2 className="text-lg font-semibold text-gray-800 dark:text-slate-100">Patient Profile</h2>

      {error && (
        <Card className="p-3 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800">
          <p className="text-sm text-red-700 dark:text-red-300">{error}</p>
        </Card>
      )}

      <Card className="p-4 space-y-3">
        <div className="flex items-center gap-2">
          <User size={16} className="text-blue-500" />
          <span className="text-sm font-semibold text-gray-900 dark:text-slate-100">{fullName}</span>
        </div>
        <div className="flex items-center gap-2 text-sm text-gray-600 dark:text-slate-300">
          <Mail size={14} />
          <span>{profile?.email || user?.email || 'N/A'}</span>
        </div>
        <div className="flex items-center gap-2 text-sm text-gray-600 dark:text-slate-300">
          <Phone size={14} />
          <span>{profile?.contactNumber || 'N/A'}</span>
        </div>
        <div className="text-sm text-gray-600 dark:text-slate-300">DOB: {profile?.dateOfBirth || 'N/A'}</div>
        <div className="text-sm text-gray-600 dark:text-slate-300">Gender: {profile?.gender || 'N/A'}</div>
        <div className="text-sm text-gray-600 dark:text-slate-300">Address: {profile?.address || 'N/A'}</div>
      </Card>
    </div>
  );
};

export default PatientProfile;
