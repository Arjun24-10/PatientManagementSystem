import React, { useState } from 'react';
import { User, Mail, Shield, Settings, Server, Lock } from 'lucide-react';
import Card from '../../components/common/Card';
import Button from '../../components/common/Button';
import Input from '../../components/common/Input';
import Badge from '../../components/common/Badge';

const Profile = () => {
    const [isEditing, setIsEditing] = useState(false);

    return (
        <div className="space-y-6">
            <h2 className="text-2xl font-bold text-gray-800 dark:text-slate-100">Admin Profile</h2>

            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                {/* Profile Card */}
                <Card className="p-6 lg:col-span-1 text-center dark:bg-slate-800">
                    <div className="w-32 h-32 rounded-full bg-slate-200 dark:bg-slate-700 mx-auto flex items-center justify-center text-slate-600 dark:text-slate-300 font-bold text-4xl mb-4">
                        AD
                    </div>
                    <h3 className="text-xl font-bold text-gray-900 dark:text-slate-100">Admin User</h3>
                    <p className="text-gray-600 dark:text-slate-400 font-medium">System Administrator</p>
                    <p className="text-gray-500 dark:text-slate-400 text-sm mt-1">Super User</p>

                    <div className="mt-6 flex justify-center space-x-2">
                        <Badge type="indigo">Admin</Badge>
                        <Badge type="green">Active</Badge>
                    </div>

                    <div className="mt-6 pt-6 border-t dark:border-slate-700 text-left space-y-3">
                        <div className="flex items-center text-gray-600 dark:text-slate-400 text-sm">
                            <Mail className="w-4 h-4 mr-3" /> admin@medicare.com
                        </div>
                        <div className="flex items-center text-gray-600 dark:text-slate-400 text-sm">
                            <Shield className="w-4 h-4 mr-3" /> Full System Access
                        </div>
                        <div className="flex items-center text-gray-600 dark:text-slate-400 text-sm">
                            <Server className="w-4 h-4 mr-3" /> Server: US-East-1
                        </div>
                    </div>
                </Card>

                {/* Personal Info & Work Details */}
                <div className="lg:col-span-2 space-y-6">
                    <Card className="p-6 dark:bg-slate-800">
                        <div className="flex justify-between items-center mb-6">
                            <h3 className="text-lg font-bold text-gray-800 dark:text-slate-100 flex items-center">
                                <User className="w-5 h-5 mr-2 text-blue-500" />
                                Admin Information
                            </h3>
                            <Button variant="outline" onClick={() => setIsEditing(!isEditing)}>
                                {isEditing ? 'Cancel' : 'Edit Details'}
                            </Button>
                        </div>

                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                            <Input label="Username" defaultValue="admin_superuser" disabled={!isEditing} />
                            <Input label="Role" defaultValue="System Administrator" disabled={true} />
                            <Input label="Email" defaultValue="admin@medicare.com" disabled={!isEditing} />
                            <Input label="Backup Email" defaultValue="backup.admin@medicare.com" disabled={!isEditing} />
                        </div>

                        {isEditing && (
                            <div className="mt-6 flex justify-end">
                                <Button onClick={() => setIsEditing(false)}>Save Changes</Button>
                            </div>
                        )}
                    </Card>

                    <Card className="p-6 dark:bg-slate-800">
                        <h3 className="text-lg font-bold text-gray-800 dark:text-slate-100 mb-4 flex items-center">
                            <Settings className="w-5 h-5 mr-2 text-blue-500" />
                            System Permissions
                        </h3>
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                            <div className="p-4 bg-gray-50 dark:bg-slate-700 rounded-lg flex justify-between items-center">
                                <span className="font-medium text-gray-800 dark:text-slate-100">User Management</span>
                                <Badge type="green">Full Access</Badge>
                            </div>
                            <div className="p-4 bg-gray-50 dark:bg-slate-700 rounded-lg flex justify-between items-center">
                                <span className="font-medium text-gray-800 dark:text-slate-100">System Logs</span>
                                <Badge type="green">View & Export</Badge>
                            </div>
                            <div className="p-4 bg-gray-50 dark:bg-slate-700 rounded-lg flex justify-between items-center">
                                <span className="font-medium text-gray-800 dark:text-slate-100">Database Access</span>
                                <Badge type="yellow">Restricted</Badge>
                            </div>
                            <div className="p-4 bg-gray-50 dark:bg-slate-700 rounded-lg flex justify-between items-center">
                                <span className="font-medium text-gray-800 dark:text-slate-100">Configuration</span>
                                <Badge type="green">Full Access</Badge>
                            </div>
                        </div>
                    </Card>

                    <Card className="p-6 dark:bg-slate-800">
                        <h3 className="text-lg font-bold text-gray-800 dark:text-slate-100 mb-4 flex items-center">
                            <Lock className="w-5 h-5 mr-2 text-blue-500" />
                            Security Settings
                        </h3>
                        <Button variant="secondary" className="w-full justify-center">Change Admin Password</Button>
                        <Button variant="outline" className="w-full justify-center mt-3 text-red-600 dark:text-red-400 border-red-200 dark:border-red-800 hover:bg-red-50 dark:hover:bg-red-900/20">Manage API Keys</Button>
                    </Card>
                </div>
            </div>
        </div>
    );
};

export default Profile;
