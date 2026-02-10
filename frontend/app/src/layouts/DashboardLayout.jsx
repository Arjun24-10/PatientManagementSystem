import React, { useState } from 'react';
import { Outlet, useNavigate, useLocation } from 'react-router-dom';
import {
    Menu, X, Home, Users, FileText, LogOut,
    Activity, Calendar, Shield, Upload, Search, Bell, ChevronDown,
    Pill, LayoutDashboard, MessageSquare, Heart, Clock, Sun, Moon
} from 'lucide-react';
import { useTheme } from '../contexts/ThemeContext';

const DashboardLayout = ({ role, userName = "User" }) => {
    const [isSidebarOpen, setIsSidebarOpen] = useState(false);
    const [isNotificationsOpen, setIsNotificationsOpen] = useState(false);
    const [isProfileOpen, setIsProfileOpen] = useState(false);
    const { isDark, toggleTheme } = useTheme();
    const navigate = useNavigate();
    const location = useLocation();

    const toggleSidebar = () => setIsSidebarOpen(!isSidebarOpen);

    const handleLogout = () => {
        navigate('/login');
    };

    const getNavItems = (role) => {
        const common = [
            { label: 'Overview', icon: Home, path: `/dashboard/${role}` },
        ];

        switch (role) {
            case 'doctor':
                return [
                    { icon: LayoutDashboard, label: 'Dashboard', path: '/dashboard/doctor' },
                    { icon: Users, label: 'Patients', path: '/dashboard/doctor/patients' },
                    { icon: Calendar, label: 'Appointments', path: '/dashboard/doctor/appointments' },
                    { icon: Activity, label: 'Lab Results', path: '/dashboard/doctor/labs' },
                    { icon: Pill, label: 'Prescriptions', path: '/dashboard/doctor/prescriptions' },
                    { icon: FileText, label: 'Reports', path: '/dashboard/doctor/reports' },
                    { icon: MessageSquare, label: 'Messages', path: '/dashboard/doctor/messages' },
                ];
            case 'patient':
                return [
                    { icon: LayoutDashboard, label: 'Overview', path: '/dashboard/patient' },
                    { icon: FileText, label: 'Medical History', path: '/dashboard/patient/history' },
                    { icon: Calendar, label: 'Appointments', path: '/dashboard/patient/appointments' },
                    { icon: Activity, label: 'Lab Results', path: '/dashboard/patient/labs' },
                    { icon: Pill, label: 'Medications', path: '/dashboard/patient/prescriptions' },
                    { icon: Shield, label: 'Privacy & Consents', path: '/dashboard/patient/consents' },
                ];

            case 'nurse':
                return [
                    ...common,
                    { label: 'Vitals', icon: Activity, path: `/dashboard/${role}/vitals` },
                    { label: 'Schedule', icon: Calendar, path: `/dashboard/${role}/schedule` },
                ];
            case 'lab':
                return [
                    ...common,
                    { label: 'Upload Results', icon: Upload, path: `/dashboard/${role}/upload` },
                    { label: 'Orders', icon: FileText, path: `/dashboard/${role}/orders` },
                    { label: 'History', icon: Clock, path: `/dashboard/${role}/history` },
                ];
            case 'admin':
                return [
                    ...common,
                    { label: 'User Management', icon: Users, path: `/dashboard/${role}/users` },
                    { label: 'System Logs', icon: Shield, path: `/dashboard/${role}/logs` },
                ];
            default:
                return common;
        }
    };

    const navItems = getNavItems(role);

    return (
        <div className="flex h-screen bg-gray-50 dark:bg-slate-900">
            {/* Mobile Sidebar Overlay */}
            {isSidebarOpen && (
                <div
                    className="fixed inset-0 z-20 bg-black/40 dark:bg-black/60 lg:hidden transition-opacity"
                    onClick={() => setIsSidebarOpen(false)}
                ></div>
            )}

            {/* Compact Sidebar */}
            <aside
                className={`fixed inset-y-0 left-0 z-30 w-56 bg-white dark:bg-slate-800 border-r border-gray-200 dark:border-slate-700 transform transition-transform duration-200 lg:translate-x-0 lg:static lg:inset-auto ${isSidebarOpen ? 'translate-x-0' : '-translate-x-full'
                    }`}
            >
                <div className="flex flex-col h-full">
                    {/* Compact Logo/Header */}
                    <div className="flex items-center justify-between h-12 px-4 border-b border-gray-200 dark:border-slate-700">
                        <div className="flex items-center gap-2">
                            <div className="w-7 h-7 bg-blue-600 dark:bg-blue-500 rounded-md flex items-center justify-center">
                                <Heart className="w-4 h-4 text-white" />
                            </div>
                            <h1 className="text-base font-semibold text-gray-800 dark:text-slate-100">
                                MediCare
                            </h1>
                        </div>
                        <button
                            onClick={() => setIsSidebarOpen(false)}
                            className="lg:hidden text-gray-500 dark:text-slate-400 hover:text-gray-700 dark:hover:text-slate-200 p-1 hover:bg-gray-100 dark:hover:bg-slate-700 rounded transition-colors"
                        >
                            <X size={18} />
                        </button>
                    </div>

                    {/* Compact Nav Links */}
                    <nav className="flex-1 px-2 py-3 space-y-0.5 overflow-y-auto">
                        {navItems.map((item) => {
                            const Icon = item.icon;
                            const isActive = location.pathname === item.path;
                            return (
                                <button
                                    key={item.path}
                                    onClick={() => navigate(item.path)}
                                    className={`flex items-center w-full px-3 py-2 text-sm font-medium rounded-md transition-colors ${isActive
                                        ? 'bg-blue-50 dark:bg-blue-900/30 text-blue-600 dark:text-blue-400'
                                        : 'text-gray-700 dark:text-slate-300 hover:bg-gray-100 dark:hover:bg-slate-700/50'
                                        }`}
                                >
                                    <Icon
                                        className={`w-4 h-4 mr-2.5 ${isActive ? 'text-blue-600 dark:text-blue-400' : 'text-gray-500 dark:text-slate-400'
                                            }`}
                                    />
                                    {item.label}
                                </button>
                            );
                        })}
                    </nav>

                    {/* Compact User Profile Section */}
                    <div className="p-2 border-t border-gray-200 dark:border-slate-700">
                        <div
                            onClick={() => navigate(`/dashboard/${role}/profile`)}
                            className="p-2 rounded-md cursor-pointer hover:bg-gray-100 dark:hover:bg-slate-700/50 transition-colors"
                        >
                            <div className="flex items-center">
                                <div className="w-8 h-8 rounded-full bg-blue-600 dark:bg-blue-500 flex items-center justify-center text-white text-sm font-semibold">
                                    {userName.charAt(0)}
                                </div>
                                <div className="ml-2 flex-1 min-w-0">
                                    <p className="text-sm font-medium text-gray-800 dark:text-slate-100 truncate">{userName}</p>
                                    <p className="text-xs text-gray-500 dark:text-slate-400 capitalize">{role}</p>
                                </div>
                            </div>
                        </div>
                        <button
                            onClick={handleLogout}
                            className="flex items-center w-full px-3 py-2 mt-1 text-sm font-medium text-red-600 dark:text-red-400 rounded-md hover:bg-red-50 dark:hover:bg-red-900/20 transition-colors"
                        >
                            <LogOut className="w-4 h-4 mr-2" />
                            Sign Out
                        </button>
                    </div>
                </div>
            </aside>

            {/* Main Content */}
            <div className="flex flex-col flex-1 overflow-hidden">
                {/* Compact Header */}
                <header className="bg-white dark:bg-slate-800 border-b border-gray-200 dark:border-slate-700 z-10">
                    <div className="flex items-center justify-between h-12 px-4">
                        <div className="flex items-center lg:hidden">
                            <button
                                onClick={toggleSidebar}
                                className="text-gray-600 dark:text-slate-400 hover:text-gray-900 dark:hover:text-slate-100 p-1.5 hover:bg-gray-100 dark:hover:bg-slate-700 rounded transition-colors"
                            >
                                <Menu size={20} />
                            </button>
                            <span className="ml-2 text-sm font-semibold text-gray-800 dark:text-slate-100">
                                MediCare
                            </span>
                        </div>

                        {/* Compact Search Bar */}
                        <div className="hidden lg:flex items-center flex-1 max-w-md ml-2">
                            <div className="relative w-full">
                                <span className="absolute inset-y-0 left-0 flex items-center pl-3">
                                    <Search className="w-4 h-4 text-gray-400 dark:text-slate-500" />
                                </span>
                                <input
                                    type="text"
                                    className="w-full py-1.5 pl-9 pr-3 text-sm text-gray-700 dark:text-slate-200 bg-gray-50 dark:bg-slate-900 border border-gray-200 dark:border-slate-700 rounded-md focus:outline-none focus:ring-1 focus:ring-blue-500 dark:focus:ring-blue-400 focus:border-blue-500 dark:focus:border-blue-400 placeholder-gray-400 dark:placeholder-slate-500"
                                    placeholder="Search..."
                                />
                            </div>
                        </div>

                        {/* Right Side Icons */}
                        <div className="flex items-center space-x-1">
                            {/* Theme Toggle Button */}
                            <button
                                onClick={toggleTheme}
                                className="p-2 text-gray-600 dark:text-slate-400 hover:bg-gray-100 dark:hover:bg-slate-700 rounded-md transition-colors"
                                title={isDark ? "Switch to Light Mode" : "Switch to Dark Mode"}
                                aria-label={isDark ? "Switch to Light Mode" : "Switch to Dark Mode"}
                            >
                                {isDark ? (
                                    <Sun className="w-4 h-4" />
                                ) : (
                                    <Moon className="w-4 h-4" />
                                )}
                            </button>

                            {/* Compact Notifications Dropdown */}
                            <div className="relative">
                                <button
                                    onClick={() => setIsNotificationsOpen(!isNotificationsOpen)}
                                    className="relative p-2 text-gray-600 dark:text-slate-400 hover:bg-gray-100 dark:hover:bg-slate-700 rounded-md transition-colors"
                                >
                                    <Bell className="w-4 h-4" />
                                    <span className="absolute top-1.5 right-1.5 w-1.5 h-1.5 bg-red-500 rounded-full"></span>
                                </button>

                                {isNotificationsOpen && (
                                    <div className="absolute right-0 mt-1 w-72 bg-white dark:bg-slate-800 rounded-md shadow-lg border border-gray-200 dark:border-slate-700 py-1 z-50">
                                        <div className="px-3 py-2 border-b border-gray-100 dark:border-slate-700 flex justify-between items-center">
                                            <h3 className="font-semibold text-gray-800 dark:text-slate-100 text-sm">Notifications</h3>
                                            <button className="text-xs text-blue-600 dark:text-blue-400 hover:text-blue-700 dark:hover:text-blue-300 font-medium">
                                                Mark all read
                                            </button>
                                        </div>
                                        <div className="max-h-56 overflow-y-auto">
                                            {[
                                                { id: 1, text: 'New lab results for Sarah Johnson', time: '5m ago', unread: true },
                                                { id: 2, text: 'Appointment with Mike Ross cancelled', time: '1h ago', unread: true },
                                                { id: 3, text: 'System maintenance scheduled', time: '1d ago', unread: false },
                                            ].map((notif) => (
                                                <div
                                                    key={notif.id}
                                                    className={`px-3 py-2 hover:bg-gray-50 dark:hover:bg-slate-700/50 cursor-pointer ${notif.unread ? 'bg-blue-50/50 dark:bg-blue-900/20' : ''
                                                        }`}
                                                >
                                                    <p className="text-sm text-gray-700 dark:text-slate-200">{notif.text}</p>
                                                    <p className="text-xs text-gray-500 dark:text-slate-400 mt-0.5">{notif.time}</p>
                                                </div>
                                            ))}
                                        </div>
                                        <div className="px-3 py-2 border-t border-gray-100 dark:border-slate-700 text-center">
                                            <button className="text-xs text-gray-600 dark:text-slate-400 hover:text-gray-800 dark:hover:text-slate-200 font-medium">
                                                View all notifications
                                            </button>
                                        </div>
                                    </div>
                                )}
                            </div>

                            {/* Compact Profile Dropdown */}
                            <div className="hidden lg:flex items-center pl-2 border-l border-gray-200 dark:border-slate-700 ml-2 relative">
                                <div
                                    onClick={() => setIsProfileOpen(!isProfileOpen)}
                                    className="flex items-center cursor-pointer hover:bg-gray-100 dark:hover:bg-slate-700 px-2 py-1 rounded-md transition-colors"
                                >
                                    <div className="w-7 h-7 rounded-full bg-blue-600 dark:bg-blue-500 flex items-center justify-center text-white text-xs font-semibold">
                                        {userName.charAt(0)}
                                    </div>
                                    <span className="ml-2 text-sm font-medium text-gray-700 dark:text-slate-200">{userName}</span>
                                    <ChevronDown className="w-3.5 h-3.5 ml-1 text-gray-500 dark:text-slate-400" />
                                </div>

                                {isProfileOpen && (
                                    <div className="absolute right-0 top-full mt-1 w-44 bg-white dark:bg-slate-800 rounded-md shadow-lg border border-gray-200 dark:border-slate-700 py-1 z-50">
                                        <div className="px-3 py-2 border-b border-gray-100 dark:border-slate-700">
                                            <p className="text-sm font-semibold text-gray-800 dark:text-slate-100">{userName}</p>
                                            <p className="text-xs text-gray-500 dark:text-slate-400 capitalize">{role}</p>
                                        </div>
                                        <button
                                            onClick={() => {
                                                navigate(`/dashboard/${role}/profile`);
                                                setIsProfileOpen(false);
                                            }}
                                            className="w-full text-left px-3 py-2 text-sm text-gray-700 dark:text-slate-300 hover:bg-gray-50 dark:hover:bg-slate-700/50 flex items-center"
                                        >
                                            <Users className="w-4 h-4 mr-2" /> Profile
                                        </button>
                                        <button className="w-full text-left px-3 py-2 text-sm text-gray-700 dark:text-slate-300 hover:bg-gray-50 dark:hover:bg-slate-700/50 flex items-center">
                                            <Shield className="w-4 h-4 mr-2" /> Settings
                                        </button>
                                        <div className="border-t border-gray-100 dark:border-slate-700 mt-1">
                                            <button
                                                onClick={handleLogout}
                                                className="w-full text-left px-3 py-2 text-sm text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-900/20 flex items-center font-medium"
                                            >
                                                <LogOut className="w-4 h-4 mr-2" /> Sign Out
                                            </button>
                                        </div>
                                    </div>
                                )}
                            </div>
                        </div>
                    </div>
                </header>

                {/* Page Content */}
                <main className="flex-1 overflow-x-hidden overflow-y-auto p-4 lg:p-5">
                    <Outlet />
                </main>
            </div>
        </div>
    );
};

export default DashboardLayout;
