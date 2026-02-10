import React, { useState } from 'react';
import { User, Mail, Phone, Shield, FileText, Heart, Activity } from 'lucide-react';
import Card from '../../components/common/Card';
import Button from '../../components/common/Button';
import Input from '../../components/common/Input';
import Badge from '../../components/common/Badge';

const Profile = () => {
    const [isEditing, setIsEditing] = useState(false);

    return (
        <div className="space-y-6">
            <h2 className="text-2xl font-bold text-gray-800 dark:text-slate-100">Patient Profile</h2>

            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                {/* Profile Card */}
                <Card className="p-6 lg:col-span-1 text-center dark:bg-slate-800">
                    <div className="w-32 h-32 rounded-full bg-green-100 dark:bg-green-900/30 mx-auto flex items-center justify-center text-green-600 dark:text-green-400 font-bold text-4xl mb-4">
                        JD
                    </div>
                    <h3 className="text-xl font-bold text-gray-900 dark:text-slate-100">John Doe</h3>
                    <p className="text-green-600 dark:text-green-400 font-medium">Patient ID: PAT-2024-001</p>
                    <p className="text-gray-500 dark:text-slate-400 text-sm mt-1">Member since Jan 2024</p>

                    <div className="mt-6 flex justify-center space-x-2">
                        <Badge type="green">Active</Badge>
                        <Badge type="purple">Insurance Active</Badge>
                    </div>

                    <div className="mt-6 pt-6 border-t dark:border-slate-700 text-left space-y-3">
                        <div className="flex items-center text-gray-600 dark:text-slate-400 text-sm">
                            <Mail className="w-4 h-4 mr-3" /> john.doe@example.com
                        </div>
                        <div className="flex items-center text-gray-600 dark:text-slate-400 text-sm">
                            <Phone className="w-4 h-4 mr-3" /> +1 (555) 987-6543
                        </div>
                        <div className="flex items-center text-gray-600 dark:text-slate-400 text-sm">
                            <Heart className="w-4 h-4 mr-3" /> Blood Type: O+
                        </div>
                    </div>
                </Card>

                {/* Personal Info & Medical Details */}
                <div className="lg:col-span-2 space-y-6">
                    <Card className="p-6 dark:bg-slate-800">
                        <div className="flex justify-between items-center mb-6">
                            <h3 className="text-lg font-bold text-gray-800 dark:text-slate-100 flex items-center">
                                <User className="w-5 h-5 mr-2 text-blue-500" />
                                Personal Information
                            </h3>
                            <Button variant="outline" onClick={() => setIsEditing(!isEditing)}>
                                {isEditing ? 'Cancel' : 'Edit Details'}
                            </Button>
                        </div>

                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                            <Input label="First Name" defaultValue="John" disabled={!isEditing} />
                            <Input label="Last Name" defaultValue="Doe" disabled={!isEditing} />
                            <Input label="Email" defaultValue="john.doe@example.com" disabled={!isEditing} />
                            <Input label="Phone" defaultValue="+1 (555) 987-6543" disabled={!isEditing} />
                            <div className="md:col-span-2">
                                <Input label="Address" defaultValue="456 Elm Street, Springfield, IL" disabled={!isEditing} />
                            </div>
                            <Input label="Date of Birth" defaultValue="1985-06-15" disabled={!isEditing} type="date" />
                            <Input label="Gender" defaultValue="Male" disabled={!isEditing} />
                        </div>

                        {isEditing && (
                            <div className="mt-6 flex justify-end">
                                <Button onClick={() => setIsEditing(false)}>Save Changes</Button>
                            </div>
                        )}
                    </Card>

                    <Card className="p-6 dark:bg-slate-800">
                        <h3 className="text-lg font-bold text-gray-800 dark:text-slate-100 mb-4 flex items-center">
                            <Activity className="w-5 h-5 mr-2 text-blue-500" />
                            Medical Overview
                        </h3>
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                            <div className="p-4 bg-gray-50 dark:bg-slate-700 rounded-lg">
                                <p className="text-sm text-gray-500 dark:text-slate-400">Primary Care Physician</p>
                                <p className="font-semibold text-gray-800 dark:text-slate-100">Dr. Sarah Smith</p>
                            </div>
                            <div className="p-4 bg-gray-50 dark:bg-slate-700 rounded-lg">
                                <p className="text-sm text-gray-500 dark:text-slate-400">Emergency Contact</p>
                                <p className="font-semibold text-gray-800 dark:text-slate-100">Jane Doe (Wife) - 555-0000</p>
                            </div>
                            <div className="p-4 bg-gray-50 dark:bg-slate-700 rounded-lg">
                                <p className="text-sm text-gray-500 dark:text-slate-400">Known Allergies</p>
                                <p className="font-semibold text-gray-800 dark:text-slate-100">Penicillin, Peanuts</p>
                            </div>
                            <div className="p-4 bg-gray-50 dark:bg-slate-700 rounded-lg">
                                <p className="text-sm text-gray-500 dark:text-slate-400">Chronic Conditions</p>
                                <p className="font-semibold text-gray-800 dark:text-slate-100">Hypertension</p>
                            </div>
                        </div>
                    </Card>

                    <Card className="p-6 dark:bg-slate-800">
                        <h3 className="text-lg font-bold text-gray-800 dark:text-slate-100 mb-4 flex items-center">
                            <Shield className="w-5 h-5 mr-2 text-blue-500" />
                            Security
                        </h3>
                        <Button variant="secondary" className="w-full justify-center">Change Password</Button>
                        <Button variant="outline" className="w-full justify-center mt-3 text-red-600 dark:text-red-400 border-red-200 dark:border-red-800 hover:bg-red-50 dark:hover:bg-red-900/20">Enable Two-Factor Authentication</Button>
                    </Card>
                </div>
            </div>
        </div>
    );
};

export default Profile;
