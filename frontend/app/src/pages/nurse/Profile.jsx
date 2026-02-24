import React, { useState } from 'react';
import { User, Mail, Phone, Shield, Thermometer, Clock } from 'lucide-react';
import { useAuth } from '../../contexts/AuthContext';
import Card from '../../components/common/Card';
import Button from '../../components/common/Button';
import Input from '../../components/common/Input';
import Badge from '../../components/common/Badge';

const Profile = () => {
    const { user } = useAuth();
    const [isEditing, setIsEditing] = useState(false);

    const displayName = user?.fullName || user?.full_name || 'Nurse';
    const email = user?.email || '';
    const initials = displayName.charAt(0);

    return (
        <div className="space-y-3">
            <h2 className="text-lg font-bold text-gray-800 dark:text-slate-100">Nurse Profile</h2>

            <div className="grid grid-cols-1 lg:grid-cols-3 gap-3">
                {/* Profile Card */}
                <Card className="p-4 lg:col-span-1 text-center dark:bg-slate-800">
                    <div className="w-20 h-20 rounded-full bg-pink-100 dark:bg-pink-900/30 mx-auto flex items-center justify-center text-pink-600 dark:text-pink-400 font-bold text-2xl mb-2">
                        {initials}
                    </div>
                    <h3 className="text-sm font-bold text-gray-900 dark:text-slate-100">{displayName}</h3>
                    <p className="text-pink-600 dark:text-pink-400 font-medium">Head Nurse (ICU)</p>
                    <p className="text-gray-500 dark:text-slate-400 text-sm mt-1">License #RN-98765-NY</p>

                    <div className="mt-3 flex justify-center space-x-2">
                        <Badge type="green">On Duty</Badge>
                        <Badge type="blue">Verified</Badge>
                    </div>

                    <div className="mt-3 pt-3 border-t dark:border-slate-700 text-left space-y-1.5">
                        <div className="flex items-center text-gray-600 dark:text-slate-400 text-xs">
                            <Mail className="w-3.5 h-3.5 mr-2" /> {email}
                        </div>
                        <div className="flex items-center text-gray-600 dark:text-slate-400 text-xs">
                            <Phone className="w-3.5 h-3.5 mr-2" /> +1 (555) 234-5678
                        </div>
                        <div className="flex items-center text-gray-600 dark:text-slate-400 text-xs">
                            <Clock className="w-3.5 h-3.5 mr-2" /> 8:00 AM - 4:00 PM
                        </div>
                    </div>
                </Card>

                {/* Personal Info & Work Details */}
                <div className="lg:col-span-2 space-y-3">
                    <Card className="p-4 dark:bg-slate-800">
                        <div className="flex justify-between items-center mb-3">
                            <h3 className="text-sm font-bold text-gray-800 dark:text-slate-100 flex items-center">
                                <User className="w-4 h-4 mr-2 text-blue-500" />
                                Personal Information
                            </h3>
                            <Button variant="outline" onClick={() => setIsEditing(!isEditing)}>
                                {isEditing ? 'Cancel' : 'Edit Details'}
                            </Button>
                        </div>

                        <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                            <Input label="Name" defaultValue={displayName} disabled={!isEditing} />
                            <Input label="Role" defaultValue="Head Nurse" disabled={!isEditing} />
                            <Input label="Email" defaultValue={email} disabled={!isEditing} />
                            <Input label="Phone" defaultValue="+1 (555) 234-5678" disabled={!isEditing} />
                            <div className="md:col-span-2">
                                <Input label="Department" defaultValue="Intensive Care Unit (ICU)" disabled={!isEditing} />
                            </div>
                        </div>

                        {isEditing && (
                            <div className="mt-3 flex justify-end">
                                <Button onClick={() => setIsEditing(false)}>Save Changes</Button>
                            </div>
                        )}
                    </Card>

                    <Card className="p-4 dark:bg-slate-800">
                        <h3 className="text-sm font-bold text-gray-800 dark:text-slate-100 mb-2 flex items-center">
                            <Thermometer className="w-4 h-4 mr-2 text-blue-500" />
                            Shift Details
                        </h3>
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                            <div className="p-2.5 bg-gray-50 dark:bg-slate-700 rounded">
                                <p className="text-xs text-gray-500 dark:text-slate-400">Current Shift</p>
                                <p className="text-sm font-semibold text-gray-800 dark:text-slate-100">Morning (8 AM - 4 PM)</p>
                            </div>
                            <div className="p-2.5 bg-gray-50 dark:bg-slate-700 rounded">
                                <p className="text-xs text-gray-500 dark:text-slate-400">Assigned Ward</p>
                                <p className="text-sm font-semibold text-gray-800 dark:text-slate-100">General Ward A</p>
                            </div>
                            <div className="p-2.5 bg-gray-50 dark:bg-slate-700 rounded">
                                <p className="text-xs text-gray-500 dark:text-slate-400">Supervisor</p>
                                <p className="text-sm font-semibold text-gray-800 dark:text-slate-100">Dr. House</p>
                            </div>
                        </div>
                    </Card>

                    <Card className="p-4 dark:bg-slate-800">
                        <h3 className="text-sm font-bold text-gray-800 dark:text-slate-100 mb-2 flex items-center">
                            <Shield className="w-4 h-4 mr-2 text-blue-500" />
                            Security
                        </h3>
                        <Button variant="secondary" className="w-full justify-center">Change Password</Button>
                        <Button variant="outline" className="w-full justify-center mt-2 text-red-600 dark:text-red-400 border-red-200 dark:border-red-800 hover:bg-red-50 dark:hover:bg-red-900/20">Enable Two-Factor Authentication</Button>
                    </Card>
                </div>
            </div>
        </div>
    );
};

export default Profile;
