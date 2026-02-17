import React, { useState } from 'react';
import { User, Mail, Phone, Shield, Beaker, CheckCircle } from 'lucide-react';
import Card from '../../components/common/Card';
import Button from '../../components/common/Button';
import Input from '../../components/common/Input';
import Badge from '../../components/common/Badge';

const Profile = () => {
    const [isEditing, setIsEditing] = useState(false);

    return (
        <div className="space-y-3">
            <h2 className="text-lg font-bold text-gray-800 dark:text-slate-100">Lab Technician Profile</h2>

            <div className="grid grid-cols-1 lg:grid-cols-3 gap-3">
                {/* Profile Card */}
                <Card className="p-4 lg:col-span-1 text-center dark:bg-slate-800">
                    <div className="w-20 h-20 rounded-full bg-purple-100 dark:bg-purple-900/30 mx-auto flex items-center justify-center text-purple-600 dark:text-purple-400 font-bold text-2xl mb-2">
                        TM
                    </div>
                    <h3 className="text-sm font-bold text-gray-900 dark:text-slate-100">Tech Mike</h3>
                    <p className="text-purple-600 dark:text-purple-400 font-medium text-xs">Senior Lab Technician</p>
                    <p className="text-gray-500 dark:text-slate-400 text-xs mt-0.5">ID #LAB-8821</p>

                    <div className="mt-3 flex justify-center space-x-1.5">
                        <Badge type="green">On Shift</Badge>
                        <Badge type="blue">Certified</Badge>
                    </div>

                    <div className="mt-3 pt-3 border-t dark:border-slate-700 text-left space-y-1.5">
                        <div className="flex items-center text-gray-600 dark:text-slate-400 text-xs">
                            <Mail className="w-3.5 h-3.5 mr-2" /> mike.tech@medicare.com
                        </div>
                        <div className="flex items-center text-gray-600 dark:text-slate-400 text-xs">
                            <Phone className="w-3.5 h-3.5 mr-2" /> +1 (555) 345-6789
                        </div>
                        <div className="flex items-center text-gray-600 dark:text-slate-400 text-xs">
                            <Beaker className="w-3.5 h-3.5 mr-2" /> Pathology Lab
                        </div>
                    </div>
                </Card>

                {/* Personal Info & Work Details */}
                <div className="lg:col-span-2 space-y-3">
                    <Card className="p-4 dark:bg-slate-800">
                        <div className="flex justify-between items-center mb-3">
                            <h3 className="text-sm font-bold text-gray-800 dark:text-slate-100 flex items-center">
                                <User className="w-4 h-4 mr-1.5 text-blue-500" />
                                Personal Information
                            </h3>
                            <Button variant="outline" size="sm" onClick={() => setIsEditing(!isEditing)}>
                                {isEditing ? 'Cancel' : 'Edit Details'}
                            </Button>
                        </div>

                        <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                            <Input label="First Name" defaultValue="Mike" disabled={!isEditing} />
                            <Input label="Last Name" defaultValue="Ross" disabled={!isEditing} />
                            <Input label="Email" defaultValue="mike.tech@medicare.com" disabled={!isEditing} />
                            <Input label="Phone" defaultValue="+1 (555) 345-6789" disabled={!isEditing} />
                            <div className="md:col-span-2">
                                <Input label="Lab Unit" defaultValue="Central Pathology Lab - Room 302" disabled={!isEditing} />
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
                            <CheckCircle className="w-4 h-4 mr-1.5 text-blue-500" />
                            Certifications
                        </h3>
                        <div className="space-y-1.5">
                            <div className="flex justify-between items-center p-2 bg-gray-50 dark:bg-slate-700 rounded-lg">
                                <span className="text-xs font-medium text-gray-800 dark:text-slate-100">Clinical Laboratory Scientist (CLS)</span>
                                <span className="text-xs text-green-600 dark:text-green-400">Active</span>
                            </div>
                            <div className="flex justify-between items-center p-2 bg-gray-50 dark:bg-slate-700 rounded-lg">
                                <span className="text-xs font-medium text-gray-800 dark:text-slate-100">Phlebotomy Technician Certification</span>
                                <span className="text-xs text-green-600 dark:text-green-400">Active</span>
                            </div>
                            <div className="flex justify-between items-center p-2 bg-gray-50 dark:bg-slate-700 rounded-lg">
                                <span className="text-xs font-medium text-gray-800 dark:text-slate-100">Safety & Hazard Certification</span>
                                <span className="text-xs text-yellow-600 dark:text-yellow-400">Expiring Soon</span>
                            </div>
                        </div>
                    </Card>

                    <Card className="p-4 dark:bg-slate-800">
                        <h3 className="text-sm font-bold text-gray-800 dark:text-slate-100 mb-2 flex items-center">
                            <Shield className="w-4 h-4 mr-1.5 text-blue-500" />
                            Security
                        </h3>
                        <Button variant="secondary" className="w-full justify-center text-xs">Change Password</Button>
                        <Button variant="outline" className="w-full justify-center mt-2 text-xs text-red-600 dark:text-red-400 border-red-200 dark:border-red-800 hover:bg-red-50 dark:hover:bg-red-900/20">Enable Two-Factor Authentication</Button>
                    </Card>
                </div>
            </div>
        </div>
    );
};

export default Profile;
