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
        <div className="flex h-screen bg-gradient-to-br from-slate-50 via-blue-50/30 to-purple-50/20 dark:from-slate-900 dark:via-slate-900 dark:to-slate-800">
            {/* Mobile Sidebar Overlay */}
            {isSidebarOpen && (
                <div
                    className="fixed inset-0 z-20 bg-black/50 dark:bg-black/70 backdrop-blur-sm lg:hidden transition-opacity"
                    onClick={() => setIsSidebarOpen(false)}
                ></div>
            )}

            {/* Premium Glassmorphism Sidebar */}
            <aside
                className={`fixed inset-y-0 left-0 z-30 w-64 glass-card border-r border-white/20 dark:border-slate-700/50 transform transition-all duration-300 ease-in-out lg:translate-x-0 lg:static lg:inset-auto ${isSidebarOpen ? 'translate-x-0' : '-translate-x-full'
                    }`}
            >
                <div className="flex flex-col h-full">
                    {/* Premium Logo/Header */}
                    <div className="flex items-center justify-between h-20 px-6 border-b border-white/10 dark:border-slate-700/50">
                        <div className="flex items-center gap-3">
                            <div className="w-10 h-10 bg-gradient-to-br from-blue-600 to-purple-600 rounded-xl flex items-center justify-center shadow-lg">
                                <Heart className="w-6 h-6 text-white" />
                            </div>
                            <h1 className="text-xl font-bold bg-gradient-to-r from-blue-600 to-purple-600 dark:from-blue-400 dark:to-purple-400 bg-clip-text text-transparent tracking-tight">
                                MediCare
                            </h1>
                        </div>
                        <button
                            onClick={() => setIsSidebarOpen(false)}
                            className="lg:hidden text-gray-500 dark:text-slate-400 hover:text-gray-700 dark:hover:text-slate-200 p-2 hover:bg-white/50 dark:hover:bg-slate-700/50 rounded-lg transition-all"
                        >
                            <X size={20} />
                        </button>
                    </div>

                    {/* Premium Nav Links */}
                    <nav className="flex-1 px-3 py-6 space-y-1 overflow-y-auto">
                        {navItems.map((item) => {
                            const Icon = item.icon;
                            const isActive = location.pathname === item.path;
                            return (
                                <button
                                    key={item.path}
                                    onClick={() => navigate(item.path)}
                                    className={`flex items-center w-full px-4 py-3 text-sm font-semibold rounded-xl transition-all duration-200 group relative ${isActive
                                        ? 'bg-gradient-to-r from-blue-500 to-purple-600 text-white shadow-lg shadow-blue-500/30'
                                        : 'text-gray-700 dark:text-slate-300 hover:bg-white/60 dark:hover:bg-slate-700/60 hover:shadow-md'
                                        }`}
                                >
                                    {isActive && (
                                        <div className="absolute left-0 w-1 h-8 bg-white rounded-r-full"></div>
                                    )}
                                    <Icon
                                        className={`w-5 h-5 mr-3 transition-all ${isActive ? 'text-white' : 'text-gray-500 dark:text-slate-400 group-hover:text-blue-600 dark:group-hover:text-blue-400'
                                            }`}
                                    />
                                    {item.label}
                                </button>
                            );
                        })}
                    </nav>

                    {/* Premium User Profile Section */}
                    <div className="p-4 border-t border-white/10 dark:border-slate-700/50">
                        <div
                            onClick={() => navigate(`/dashboard/${role}/profile`)}
                            className="glass-card-dark p-4 rounded-xl mb-3 cursor-pointer hover:bg-white/10 transition-colors group"
                        >
                            <div className="flex items-center">
                                <div className="w-10 h-10 rounded-full bg-gradient-to-br from-blue-500 to-purple-600 flex items-center justify-center text-white font-bold shadow-lg group-hover:scale-105 transition-transform">
                                    {userName.charAt(0)}
                                </div>
                                <div className="ml-3 flex-1">
                                    <p className="text-sm font-bold text-gray-800 dark:text-slate-100 group-hover:text-blue-600 dark:group-hover:text-blue-400 transition-colors">{userName}</p>
                                    <p className="text-xs text-gray-600 dark:text-slate-400 capitalize">{role}</p>
                                </div>
                            </div>
                        </div>
                        <button
                            onClick={handleLogout}
                            className="flex items-center w-full px-4 py-2.5 text-sm font-semibold text-red-600 dark:text-red-400 rounded-xl hover:bg-red-50 dark:hover:bg-red-900/20 transition-all hover:shadow-md"
                        >
                            <LogOut className="w-5 h-5 mr-3" />
                            Sign Out
                        </button>
                    </div>
                </div>
            </aside>

            {/* Main Content */}
            <div className="flex flex-col flex-1 overflow-hidden">
                {/* Premium Glassmorphism Header */}
                <header className="glass-card border-b border-white/20 dark:border-slate-700/50 z-10">
                    <div className="flex items-center justify-between h-16 px-6">
                        <div className="flex items-center lg:hidden">
                            <button
                                onClick={toggleSidebar}
                                className="text-gray-600 dark:text-slate-400 hover:text-gray-900 dark:hover:text-slate-100 p-2 hover:bg-white/50 dark:hover:bg-slate-700/50 rounded-lg transition-all"
                            >
                                <Menu size={24} />
                            </button>
                            <span className="ml-3 text-lg font-bold bg-gradient-to-r from-blue-600 to-purple-600 dark:from-blue-400 dark:to-purple-400 bg-clip-text text-transparent">
                                MediCare
                            </span>
                        </div>

                        {/* Premium Search Bar */}
                        <div className="hidden lg:flex items-center flex-1 max-w-xl ml-4">
                            <div className="relative w-full">
                                <span className="absolute inset-y-0 left-0 flex items-center pl-4">
                                    <Search className="w-5 h-5 text-gray-400 dark:text-slate-500" />
                                </span>
                                <input
                                    type="text"
                                    className="w-full py-2.5 pl-12 pr-4 text-sm text-gray-700 dark:text-slate-200 bg-white/60 dark:bg-slate-800/60 backdrop-blur-sm border border-white/40 dark:border-slate-700/50 rounded-xl focus:outline-none focus:ring-2 focus:ring-blue-500 dark:focus:ring-blue-400 focus:bg-white dark:focus:bg-slate-800 transition-all shadow-sm placeholder-gray-500 dark:placeholder-slate-500"
                                    placeholder="Search patients, appointments, or reports..."
                                />
                            </div>
                        </div>

                        {/* Right Side Icons */}
                        <div className="flex items-center space-x-3">
                            {/* Theme Toggle Button */}
                            <button
                                onClick={toggleTheme}
                                className="p-2.5 text-gray-600 dark:text-slate-400 hover:bg-white/60 dark:hover:bg-slate-700/50 rounded-xl transition-all hover:shadow-md"
                                title={isDark ? "Switch to Light Mode" : "Switch to Dark Mode"}
                                aria-label={isDark ? "Switch to Light Mode" : "Switch to Dark Mode"}
                            >
                                {isDark ? (
                                    <Sun className="w-5 h-5" />
                                ) : (
                                    <Moon className="w-5 h-5" />
                                )}
                            </button>

                            {/* Premium Notifications Dropdown */}
                            <div className="relative">
                                <button
                                    onClick={() => setIsNotificationsOpen(!isNotificationsOpen)}
                                    className="relative p-2.5 text-gray-600 dark:text-slate-400 hover:bg-white/60 dark:hover:bg-slate-700/50 rounded-xl transition-all hover:shadow-md"
                                >
                                    <Bell className="w-5 h-5" />
                                    <span className="absolute top-2 right-2 w-2 h-2 bg-gradient-to-r from-red-500 to-pink-500 rounded-full border-2 border-white dark:border-slate-800 shadow-sm"></span>
                                </button>

                                {isNotificationsOpen && (
                                    <div className="absolute right-0 mt-2 w-80 bg-white dark:bg-slate-800 rounded-2xl shadow-xl border border-gray-100 dark:border-slate-700 py-2 z-50 animate-fade-in">
                                        <div className="px-4 py-3 border-b border-gray-100 dark:border-slate-700 flex justify-between items-center">
                                            <h3 className="font-bold text-gray-800 dark:text-slate-100 text-sm">Notifications</h3>
                                            <button className="text-xs text-blue-600 dark:text-blue-400 hover:text-blue-700 dark:hover:text-blue-300 font-semibold">
                                                Mark all read
                                            </button>
                                        </div>
                                        <div className="max-h-64 overflow-y-auto">
                                            {[
                                                { id: 1, text: 'New lab results for Sarah Johnson', time: '5m ago', unread: true },
                                                { id: 2, text: 'Appointment with Mike Ross cancelled', time: '1h ago', unread: true },
                                                { id: 3, text: 'System maintenance scheduled', time: '1d ago', unread: false },
                                            ].map((notif) => (
                                                <div
                                                    key={notif.id}
                                                    className={`px-4 py-3 hover:bg-gray-50 dark:hover:bg-slate-700/50 cursor-pointer transition-all ${notif.unread ? 'bg-blue-50/50 dark:bg-blue-900/20' : ''
                                                        }`}
                                                >
                                                    <p className="text-sm text-gray-700 dark:text-slate-200 font-medium">{notif.text}</p>
                                                    <p className="text-xs text-gray-500 dark:text-slate-400 mt-1">{notif.time}</p>
                                                </div>
                                            ))}
                                        </div>
                                        <div className="px-4 py-2 border-t border-gray-100 dark:border-slate-700 text-center">
                                            <button className="text-xs text-gray-600 dark:text-slate-400 hover:text-gray-800 dark:hover:text-slate-200 font-semibold">
                                                View all notifications
                                            </button>
                                        </div>
                                    </div>
                                )}
                            </div>

                            {/* Premium Profile Dropdown */}
                            <div className="hidden lg:flex items-center pl-3 border-l border-white/20 dark:border-slate-700/50 relative">
                                <div
                                    onClick={() => setIsProfileOpen(!isProfileOpen)}
                                    className="flex items-center cursor-pointer hover:bg-white/60 dark:hover:bg-slate-700/50 px-3 py-2 rounded-xl transition-all"
                                >
                                    <div className="w-9 h-9 rounded-full bg-gradient-to-br from-blue-500 to-purple-600 flex items-center justify-center text-white font-bold shadow-lg">
                                        {userName.charAt(0)}
                                    </div>
                                    <span className="ml-2 text-sm font-semibold text-gray-700 dark:text-slate-200">{userName}</span>
                                    <ChevronDown className="w-4 h-4 ml-1 text-gray-500 dark:text-slate-400" />
                                </div>

                                {isProfileOpen && (
                                    <div className="absolute right-0 top-full mt-2 w-48 bg-white dark:bg-slate-800 rounded-2xl shadow-xl border border-gray-100 dark:border-slate-700 py-1 z-50 animate-fade-in">
                                        <div className="px-4 py-3 border-b border-gray-100 dark:border-slate-700">
                                            <p className="text-sm font-bold text-gray-800 dark:text-slate-100">{userName}</p>
                                            <p className="text-xs text-gray-600 dark:text-slate-400 capitalize">{role}</p>
                                        </div>
                                        <button
                                            onClick={() => {
                                                navigate(`/dashboard/${role}/profile`);
                                                setIsProfileOpen(false);
                                            }}
                                            className="w-full text-left px-4 py-2.5 text-sm text-gray-700 dark:text-slate-300 hover:bg-gray-50 dark:hover:bg-slate-700/50 flex items-center font-medium transition-all"
                                        >
                                            <Users className="w-4 h-4 mr-2" /> Profile
                                        </button>
                                        <button className="w-full text-left px-4 py-2.5 text-sm text-gray-700 dark:text-slate-300 hover:bg-gray-50 dark:hover:bg-slate-700/50 flex items-center font-medium transition-all">
                                            <Shield className="w-4 h-4 mr-2" /> Settings
                                        </button>
                                        <div className="border-t border-gray-100 dark:border-slate-700 mt-1">
                                            <button
                                                onClick={handleLogout}
                                                className="w-full text-left px-4 py-2.5 text-sm text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-900/20 flex items-center font-semibold transition-all rounded-b-2xl"
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

                {/* Page Content with Premium Background */}
                <main className="flex-1 overflow-x-hidden overflow-y-auto p-6 lg:p-8">
                    <Outlet />
                </main>
            </div>
        </div>
    );
};

export default DashboardLayout;
