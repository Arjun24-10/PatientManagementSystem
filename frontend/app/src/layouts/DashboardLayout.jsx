import React, { useState } from 'react';
import { Outlet, useNavigate } from 'react-router-dom';
import {
    Menu, Search, Bell, Sun, Moon
} from 'lucide-react';
import { useTheme } from '../contexts/ThemeContext';
import { useAuth } from '../contexts/AuthContext';
import Sidebar from '../components/layout/Sidebar';

const DashboardLayout = ({ role, userName = "User" }) => {
    const [isSidebarOpen, setIsSidebarOpen] = useState(false);
    const [isCollapsed, setIsCollapsed] = useState(false);
    const [isNotificationsOpen, setIsNotificationsOpen] = useState(false);
    const { isDark, toggleTheme } = useTheme();
    const { logout } = useAuth();
    const navigate = useNavigate();

    const toggleSidebar = () => setIsSidebarOpen(!isSidebarOpen);
    const toggleCollapse = () => setIsCollapsed(!isCollapsed);

    const handleLogout = async () => {
        try {
            await logout();
            navigate('/login');
        } catch (error) {
            console.error("Failed to log out", error);
        }
    };

    return (
        <div className="flex h-screen bg-gray-50 dark:bg-slate-900 transition-colors duration-200">
            {/* Mobile Sidebar Overlay */}
            {isSidebarOpen && (
                <div
                    className="fixed inset-0 z-20 bg-black/40 dark:bg-black/60 lg:hidden transition-opacity backdrop-blur-sm"
                    onClick={() => setIsSidebarOpen(false)}
                ></div>
            )}

            <Sidebar
                role={role}
                userName={userName}
                isOpen={isSidebarOpen}
                setIsOpen={setIsSidebarOpen}
                isCollapsed={isCollapsed}
                toggleCollapse={toggleCollapse}
                onLogout={handleLogout}
            />

            {/* Main Content */}
            <div className="flex flex-col flex-1 overflow-hidden">
                {/* Compact Header */}
                <header className="bg-white dark:bg-slate-800 border-b border-gray-200 dark:border-slate-700 z-10 transition-colors duration-200">
                    <div className="flex items-center justify-between h-16 px-4">
                        {/* Mobile Header: Menu & Logo */}
                        <div className="flex items-center lg:hidden gap-3">
                            <button
                                onClick={toggleSidebar}
                                className="text-gray-600 dark:text-slate-400 hover:text-gray-900 dark:hover:text-slate-100 p-2 hover:bg-gray-100 dark:hover:bg-slate-700 rounded-lg transition-colors"
                            >
                                <Menu size={20} />
                            </button>
                            <span className="text-lg font-bold text-gray-800 dark:text-slate-100 tracking-tight">
                                MediCare
                            </span>
                        </div>

                        {/* Desktop Search Bar */}
                        <div className="hidden lg:flex items-center flex-1 max-w-xl mx-4">
                            <div className="relative w-full group">
                                <span className="absolute inset-y-0 left-0 flex items-center pl-3 pointer-events-none">
                                    <Search className="w-4 h-4 text-gray-400 group-focus-within:text-blue-500 transition-colors" />
                                </span>
                                <input
                                    type="text"
                                    className="w-full py-2 pl-10 pr-4 text-sm text-gray-700 dark:text-slate-200 bg-gray-50 dark:bg-slate-900 border border-gray-200 dark:border-slate-700 rounded-xl focus:outline-none focus:ring-2 focus:ring-blue-500/20 focus:border-blue-500 transition-all"
                                    placeholder="Search patients, appointments, or records..."
                                />
                            </div>
                        </div>

                        {/* Right Actions */}
                        <div className="flex items-center gap-2">
                            <button
                                onClick={toggleTheme}
                                className="p-2 text-gray-500 dark:text-slate-400 hover:bg-gray-100 dark:hover:bg-slate-700 rounded-lg transition-colors"
                                title={isDark ? "Switch to Light Mode" : "Switch to Dark Mode"}
                            >
                                {isDark ? <Sun className="w-5 h-5" /> : <Moon className="w-5 h-5" />}
                            </button>

                            <div className="relative">
                                <button
                                    onClick={() => setIsNotificationsOpen(!isNotificationsOpen)}
                                    className="relative p-2 text-gray-500 dark:text-slate-400 hover:bg-gray-100 dark:hover:bg-slate-700 rounded-lg transition-colors"
                                >
                                    <Bell className="w-5 h-5" />
                                </button>

                                {isNotificationsOpen && (
                                    <div className="absolute right-0 mt-2 w-80 bg-white dark:bg-slate-800 rounded-xl shadow-xl border border-gray-100 dark:border-slate-700 py-2 z-50 animate-in fade-in zoom-in-95 duration-200">
                                        <div className="px-4 py-3 border-b border-gray-100 dark:border-slate-700 flex justify-between items-center">
                                            <h3 className="font-semibold text-gray-900 dark:text-slate-100">Notifications</h3>
                                            <button
                                                className="text-xs font-medium text-blue-600 dark:text-blue-400 hover:text-blue-700"
                                                onClick={() => setIsNotificationsOpen(false)}
                                            >
                                                Close
                                            </button>
                                        </div>
                                        <div className="px-4 py-6 text-center text-sm text-gray-500 dark:text-slate-400">
                                            No new notifications
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
