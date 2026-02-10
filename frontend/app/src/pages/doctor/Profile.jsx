import React, { useState } from 'react';
import { User, Mail, Phone, Award, Clock, Shield } from 'lucide-react';
import Card from '../../components/common/Card';
import Button from '../../components/common/Button';
import Input from '../../components/common/Input';
import Badge from '../../components/common/Badge';

const Profile = () => {
    const [isEditing, setIsEditing] = useState(false);

    return (
        <div className="space-y-3">
            <h2 className="text-lg font-bold text-gray-800 dark:text-slate-100">Doctor Profile</h2>

            <div className="grid grid-cols-1 lg:grid-cols-3 gap-3">
                {/* Profile Card */}
                <Card className="p-4 lg:col-span-1 text-center dark:bg-slate-800">
                    <div className="w-20 h-20 rounded-full bg-blue-100 dark:bg-blue-900/30 mx-auto flex items-center justify-center text-blue-600 dark:text-blue-400 font-bold text-2xl mb-2">
                        DS
                    </div>
                    <h3 className="text-sm font-bold text-gray-900 dark:text-slate-100">Dr. Sarah Smith</h3>
                    <p className="text-xs text-blue-600 dark:text-blue-400 font-medium">Cardiologist (MBBS, MD)</p>
                    <p className="text-gray-500 dark:text-slate-400 text-xs">License #MD-12345-NY</p>

                    <div className="mt-3 flex justify-center space-x-1">
                        <Badge type="green">Active Status</Badge>
                        <Badge type="blue">Verified</Badge>
                    </div>

                    <div className="mt-3 pt-3 border-t dark:border-slate-700 text-left space-y-1.5">
                        <div className="flex items-center text-gray-600 dark:text-slate-400 text-xs">
                            <Mail className="w-3.5 h-3.5 mr-2" /> sarah.smith@medicare.com
                        </div>
                        <div className="flex items-center text-gray-600 dark:text-slate-400 text-xs">
                            <Phone className="w-3.5 h-3.5 mr-2" /> +1 (555) 123-4567
                        </div>
                        <div className="flex items-center text-gray-600 dark:text-slate-400 text-xs">
                            <Award className="w-3.5 h-3.5 mr-2" /> 15 Years Experience
                        </div>
                    </div>
                </Card>

                {/* Settings & Schedule */}
                <div className="lg:col-span-2 space-y-3">
                    <Card className="p-4 dark:bg-slate-800">
                        <div className="flex justify-between items-center mb-3">
                            <h3 className="text-sm font-bold text-gray-800 dark:text-slate-100 flex items-center">
                                <User className="w-4 h-4 mr-1.5 text-blue-500" />
                                Personal Information
                            </h3>
                            <Button variant="outline" className="text-xs" onClick={() => setIsEditing(!isEditing)}>
                                {isEditing ? 'Cancel' : 'Edit Details'}
                            </Button>
                        </div>

                        <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                            <Input label="First Name" defaultValue="Sarah" disabled={!isEditing} />
                            <Input label="Last Name" defaultValue="Smith" disabled={!isEditing} />
                            <Input label="Email" defaultValue="sarah.smith@medicare.com" disabled={!isEditing} />
                            <Input label="Phone" defaultValue="+1 (555) 123-4567" disabled={!isEditing} />
                            <div className="md:col-span-2">
                                <Input label="Clinic Address" defaultValue="123 Medical Center Dr, Suite 400" disabled={!isEditing} />
                            </div>
                        </div>

                        {isEditing && (
                            <div className="mt-3 flex justify-end">
                                <Button className="text-sm" onClick={() => setIsEditing(false)}>Save Changes</Button>
                            </div>
                        )}
                    </Card>

                    <Card className="p-4 dark:bg-slate-800">
                        <h3 className="text-sm font-bold text-gray-800 dark:text-slate-100 mb-2 flex items-center">
                            <Clock className="w-4 h-4 mr-1.5 text-blue-500" />
                            Availability Settings
                        </h3>
                        <div className="space-y-2">
                            <div className="flex items-center justify-between p-2 bg-gray-50 dark:bg-slate-700 rounded">
                                <div>
                                    <p className="font-medium text-sm text-gray-800 dark:text-slate-100">Accepting New Patients</p>
                                    <p className="text-xs text-gray-500 dark:text-slate-400">Allow new patients to book appointments</p>
                                </div>
                                <div className="relative inline-block w-10 h-5 transition duration-200 ease-in-out bg-blue-600 rounded-full cursor-pointer">
                                    <span className="absolute left-0.5 top-0.5 bg-white w-4 h-4 rounded-full transition-transform transform translate-x-5"></span>
                                </div>
                            </div>
                            <div className="flex items-center justify-between p-2 bg-gray-50 dark:bg-slate-700 rounded">
                                <div>
                                    <p className="font-medium text-sm text-gray-800 dark:text-slate-100">Show Phone Number</p>
                                    <p className="text-xs text-gray-500 dark:text-slate-400">Display contact number on public profile</p>
                                </div>
                                <div className="relative inline-block w-10 h-5 transition duration-200 ease-in-out bg-gray-300 dark:bg-slate-600 rounded-full cursor-pointer">
                                    <span className="absolute left-0.5 top-0.5 bg-white w-4 h-4 rounded-full transition-transform transform translate-x-0"></span>
                                </div>
                            </div>
                        </div>
                    </Card>

                    <Card className="p-4 dark:bg-slate-800">
                        <h3 className="text-sm font-bold text-gray-800 dark:text-slate-100 mb-2 flex items-center">
                            <Shield className="w-4 h-4 mr-1.5 text-blue-500" />
                            Security
                        </h3>
                        <Button variant="secondary" className="w-full justify-center text-sm">Change Password</Button>
                        <Button variant="outline" className="w-full justify-center mt-2 text-xs text-red-600 dark:text-red-400 border-red-200 dark:border-red-800 hover:bg-red-50 dark:hover:bg-red-900/20">Enable Two-Factor Authentication</Button>
                    </Card>
                </div>
            </div>
        </div>
    );
};

export default Profile;
