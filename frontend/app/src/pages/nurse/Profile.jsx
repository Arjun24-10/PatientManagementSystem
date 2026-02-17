import React, { useState } from 'react';
import { User, Mail, Phone, Shield, Stethoscope, Clock, MapPin, Calendar } from 'lucide-react';
import Card from '../../components/common/Card';
import Button from '../../components/common/Button';
import Input from '../../components/common/Input';
import Badge from '../../components/common/Badge';

const NurseProfile = () => {
    const [isEditing, setIsEditing] = useState(false);

    // Mock nurse data - in production, this would come from auth context or API
    const nurseData = {
        firstName: 'Joy',
        lastName: 'Pokemon',
        email: 'nurse.joy@medicare.com',
        phone: '+1 (555) 234-5678',
        license: 'RN-98765-NY',
        department: 'Intensive Care Unit (ICU)',
        role: 'Head Nurse',
        shift: 'Morning (8 AM - 4 PM)',
        ward: 'General Ward A',
        supervisor: 'Dr. House',
        status: 'On Duty',
    };

    return (
        <div className="space-y-4">
            <div className="flex items-center justify-between">
                <h1 className="text-lg font-bold text-gray-900 dark:text-slate-100">Nurse Profile</h1>
                <Badge type="green" className="flex items-center gap-1">
                    <div className="w-2 h-2 bg-green-500 rounded-full animate-pulse" />
                    {nurseData.status}
                </Badge>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
                {/* Profile Card */}
                <Card className="p-4 lg:col-span-1">
                    <div className="text-center">
                        <div className="w-20 h-20 rounded-full bg-blue-100 dark:bg-blue-900/30 mx-auto flex items-center justify-center text-blue-600 dark:text-blue-400 font-bold text-2xl mb-3">
                            {nurseData.firstName[0]}
                            {nurseData.lastName[0]}
                        </div>
                        <h3 className="text-base font-bold text-gray-900 dark:text-slate-100">
                            {nurseData.firstName} {nurseData.lastName}
                        </h3>
                        <p className="text-blue-600 dark:text-blue-400 font-medium text-sm mt-1">
                            {nurseData.role}
                        </p>
                        <p className="text-gray-500 dark:text-slate-400 text-xs mt-1">
                            License #{nurseData.license}
                        </p>

                        <div className="mt-4 flex justify-center gap-2">
                            <Badge type="blue" size="sm">
                                Verified
                            </Badge>
                            <Badge type="green" size="sm">
                                Active
                            </Badge>
                        </div>

                        <div className="mt-4 pt-4 border-t border-gray-200 dark:border-slate-700 text-left space-y-2">
                            <div className="flex items-center text-gray-600 dark:text-slate-400 text-xs">
                                <Mail className="w-3.5 h-3.5 mr-2 flex-shrink-0" />
                                <span className="truncate">{nurseData.email}</span>
                            </div>
                            <div className="flex items-center text-gray-600 dark:text-slate-400 text-xs">
                                <Phone className="w-3.5 h-3.5 mr-2 flex-shrink-0" />
                                {nurseData.phone}
                            </div>
                            <div className="flex items-center text-gray-600 dark:text-slate-400 text-xs">
                                <Stethoscope className="w-3.5 h-3.5 mr-2 flex-shrink-0" />
                                {nurseData.department}
                            </div>
                            <div className="flex items-center text-gray-600 dark:text-slate-400 text-xs">
                                <Clock className="w-3.5 h-3.5 mr-2 flex-shrink-0" />
                                {nurseData.shift}
                            </div>
                        </div>
                    </div>
                </Card>

                {/* Details Section */}
                <div className="lg:col-span-2 space-y-4">
                    {/* Personal Information */}
                    <Card className="p-4">
                        <div className="flex justify-between items-center mb-4">
                            <h3 className="text-sm font-bold text-gray-900 dark:text-slate-100 flex items-center gap-2">
                                <User className="w-4 h-4 text-blue-600 dark:text-blue-400" />
                                Personal Information
                            </h3>
                            <Button
                                variant="outline"
                                size="sm"
                                onClick={() => setIsEditing(!isEditing)}
                            >
                                {isEditing ? 'Cancel' : 'Edit'}
                            </Button>
                        </div>

                        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                            <Input
                                label="First Name"
                                defaultValue={nurseData.firstName}
                                disabled={!isEditing}
                            />
                            <Input
                                label="Last Name"
                                defaultValue={nurseData.lastName}
                                disabled={!isEditing}
                            />
                            <Input
                                label="Email"
                                type="email"
                                defaultValue={nurseData.email}
                                disabled={!isEditing}
                            />
                            <Input
                                label="Phone"
                                type="tel"
                                defaultValue={nurseData.phone}
                                disabled={!isEditing}
                            />
                            <div className="md:col-span-2">
                                <Input
                                    label="Department"
                                    defaultValue={nurseData.department}
                                    disabled={!isEditing}
                                />
                            </div>
                        </div>

                        {isEditing && (
                            <div className="mt-4 flex justify-end gap-2">
                                <Button variant="outline" size="sm" onClick={() => setIsEditing(false)}>
                                    Cancel
                                </Button>
                                <Button size="sm" onClick={() => setIsEditing(false)}>
                                    Save Changes
                                </Button>
                            </div>
                        )}
                    </Card>

                    {/* Work Details */}
                    <Card className="p-4">
                        <h3 className="text-sm font-bold text-gray-900 dark:text-slate-100 mb-3 flex items-center gap-2">
                            <Calendar className="w-4 h-4 text-blue-600 dark:text-blue-400" />
                            Work Details
                        </h3>
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                            <div className="p-3 bg-gray-50 dark:bg-slate-800/50 rounded-lg border border-gray-200 dark:border-slate-700">
                                <p className="text-xs text-gray-500 dark:text-slate-400 mb-1">
                                    Current Shift
                                </p>
                                <p className="text-sm font-semibold text-gray-900 dark:text-slate-100">
                                    {nurseData.shift}
                                </p>
                            </div>
                            <div className="p-3 bg-gray-50 dark:bg-slate-800/50 rounded-lg border border-gray-200 dark:border-slate-700">
                                <p className="text-xs text-gray-500 dark:text-slate-400 mb-1">
                                    Assigned Ward
                                </p>
                                <p className="text-sm font-semibold text-gray-900 dark:text-slate-100">
                                    {nurseData.ward}
                                </p>
                            </div>
                            <div className="p-3 bg-gray-50 dark:bg-slate-800/50 rounded-lg border border-gray-200 dark:border-slate-700">
                                <p className="text-xs text-gray-500 dark:text-slate-400 mb-1">Supervisor</p>
                                <p className="text-sm font-semibold text-gray-900 dark:text-slate-100">
                                    {nurseData.supervisor}
                                </p>
                            </div>
                            <div className="p-3 bg-gray-50 dark:bg-slate-800/50 rounded-lg border border-gray-200 dark:border-slate-700">
                                <p className="text-xs text-gray-500 dark:text-slate-400 mb-1">
                                    License Number
                                </p>
                                <p className="text-sm font-semibold text-gray-900 dark:text-slate-100">
                                    {nurseData.license}
                                </p>
                            </div>
                        </div>
                    </Card>

                    {/* Security Settings */}
                    <Card className="p-4">
                        <h3 className="text-sm font-bold text-gray-900 dark:text-slate-100 mb-3 flex items-center gap-2">
                            <Shield className="w-4 h-4 text-blue-600 dark:text-blue-400" />
                            Security Settings
                        </h3>
                        <div className="space-y-2">
                            <Button variant="outline" className="w-full justify-center">
                                Change Password
                            </Button>
                            <Button
                                variant="outline"
                                className="w-full justify-center text-blue-600 dark:text-blue-400 border-blue-200 dark:border-blue-800 hover:bg-blue-50 dark:hover:bg-blue-900/20"
                            >
                                Enable Two-Factor Authentication
                            </Button>
                        </div>
                    </Card>
                </div>
            </div>
        </div>
    );
};

export default NurseProfile;
