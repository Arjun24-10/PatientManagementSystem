import React, { useState } from 'react';
import { User, Mail, Phone, Shield, Heart, Activity } from 'lucide-react';
import { useAuth } from '../../contexts/AuthContext';
import Card from '../../components/common/Card';
import Button from '../../components/common/Button';
import Input from '../../components/common/Input';
import Badge from '../../components/common/Badge';

const Profile = () => {
    const { user } = useAuth();
    const [isEditing, setIsEditing] = useState(false);

    const displayName = user?.fullName || user?.full_name || 'Patient';
    const email = user?.email || '';
    const initials = displayName.charAt(0);

    return (
        <div className="space-y-3">
            <h2 className="text-lg font-bold text-gray-800 dark:text-slate-100">Patient Profile</h2>

            <div className="grid grid-cols-1 lg:grid-cols-3 gap-3">
                {/* Profile Card */}
                <Card className="p-4 lg:col-span-1 text-center dark:bg-slate-800">
                    <div className="w-20 h-20 rounded-full bg-green-100 dark:bg-green-900/30 mx-auto flex items-center justify-center text-green-600 dark:text-green-400 font-bold text-2xl mb-2">
                        {initials}
                    </div>
                    <h3 className="text-sm font-bold text-gray-900 dark:text-slate-100">{displayName}</h3>
                    <p className="text-green-600 dark:text-green-400 font-medium text-xs">Patient ID: PAT-2024-001</p>
                    <p className="text-gray-500 dark:text-slate-400 text-xs mt-0.5">Member since Jan 2024</p>

                    <div className="mt-3 flex justify-center space-x-1.5">
                        <Badge type="green">Active</Badge>
                        <Badge type="purple">Insurance Active</Badge>
                    </div>

                    <div className="mt-3 pt-3 border-t dark:border-slate-700 text-left space-y-2">
                        <div className="flex items-center text-gray-600 dark:text-slate-400 text-xs">
                            <Mail className="w-3.5 h-3.5 mr-2" /> {email}
                        </div>
                        <div className="flex items-center text-gray-600 dark:text-slate-400 text-xs">
                            <Phone className="w-3.5 h-3.5 mr-2" /> +1 (555) 987-6543
                        </div>
                        <div className="flex items-center text-gray-600 dark:text-slate-400 text-xs">
                            <Heart className="w-3.5 h-3.5 mr-2" /> Blood Type: O+
                        </div>
                    </div>
                </Card>

                {/* Personal Info & Medical Details */}
                <div className="lg:col-span-2 space-y-3">
                    <Card className="p-4 dark:bg-slate-800">
                        <div className="flex justify-between items-center mb-3">
                            <h3 className="text-sm font-bold text-gray-800 dark:text-slate-100 flex items-center">
                                <User className="w-4 h-4 mr-1.5 text-blue-500" />
                                Personal Information
                            </h3>
                            <Button variant="outline" className="text-xs py-1 px-2" onClick={() => setIsEditing(!isEditing)}>
                                {isEditing ? 'Cancel' : 'Edit'}
                            </Button>
                        </div>

                        <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                            <Input label="Name" defaultValue={displayName} disabled={!isEditing} />
                            <Input label="Email" defaultValue={email} disabled={!isEditing} />
                            <Input label="Phone" defaultValue="+1 (555) 987-6543" disabled={!isEditing} />
                            <div className="md:col-span-2">
                                <Input label="Address" defaultValue="456 Elm Street, Springfield, IL" disabled={!isEditing} />
                            </div>
                            <Input label="Date of Birth" defaultValue="1985-06-15" disabled={!isEditing} type="date" />
                            <Input label="Gender" defaultValue="Male" disabled={!isEditing} />
                        </div>

                        {isEditing && (
                            <div className="mt-3 flex justify-end">
                                <Button className="text-xs py-1.5 px-3" onClick={() => setIsEditing(false)}>Save Changes</Button>
                            </div>
                        )}
                    </Card>

                    <Card className="p-4 dark:bg-slate-800">
                        <h3 className="text-sm font-bold text-gray-800 dark:text-slate-100 mb-2 flex items-center">
                            <Activity className="w-4 h-4 mr-1.5 text-blue-500" />
                            Medical Overview
                        </h3>
                        <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
                            <div className="p-2 bg-gray-50 dark:bg-slate-700 rounded">
                                <p className="text-xs text-gray-500 dark:text-slate-400">Primary Care Physician</p>
                                <p className="font-semibold text-gray-800 dark:text-slate-100 text-xs">Dr. Sarah Smith</p>
                            </div>
                            <div className="p-2 bg-gray-50 dark:bg-slate-700 rounded">
                                <p className="text-xs text-gray-500 dark:text-slate-400">Emergency Contact</p>
                                <p className="font-semibold text-gray-800 dark:text-slate-100 text-xs">Jane Doe (Wife)</p>
                            </div>
                            <div className="p-2 bg-gray-50 dark:bg-slate-700 rounded">
                                <p className="text-xs text-gray-500 dark:text-slate-400">Known Allergies</p>
                                <p className="font-semibold text-gray-800 dark:text-slate-100 text-xs">Penicillin, Peanuts</p>
                            </div>
                            <div className="p-2 bg-gray-50 dark:bg-slate-700 rounded">
                                <p className="text-xs text-gray-500 dark:text-slate-400">Chronic Conditions</p>
                                <p className="font-semibold text-gray-800 dark:text-slate-100 text-xs">Hypertension</p>
                            </div>
                        </div>
                    </Card>

                    <Card className="p-4 dark:bg-slate-800">
                        <h3 className="text-sm font-bold text-gray-800 dark:text-slate-100 mb-2 flex items-center">
                            <Shield className="w-4 h-4 mr-1.5 text-blue-500" />
                            Security
                        </h3>
                        <Button variant="secondary" className="w-full justify-center text-xs py-1.5">Change Password</Button>
                        <Button variant="outline" className="w-full justify-center mt-2 text-xs py-1.5 text-red-600 dark:text-red-400 border-red-200 dark:border-red-800 hover:bg-red-50 dark:hover:bg-red-900/20">Enable Two-Factor Auth</Button>
                    </Card>
                </div>
            </div>
        </div>
    );
};

export default Profile;
