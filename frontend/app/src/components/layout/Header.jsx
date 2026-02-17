import React, { useState } from 'react';
import { Menu, Search, Bell, Sun, Moon, ChevronDown, Users, Shield, LogOut } from 'lucide-react';
import { useTheme } from '../../contexts/ThemeContext';
import { useNavigate } from 'react-router-dom';

const Header = ({
    role,
    userName,
    onToggleSidebar,
    onLogout,
    isNotificationsOpen,
    setIsNotificationsOpen,
    isProfileOpen,
    setIsProfileOpen
}) => {
    const { isDark, toggleTheme } = useTheme();
    const navigate = useNavigate();

    return (
        <header className="bg-white dark:bg-slate-800 border-b border-gray-200 dark:border-slate-700 sticky top-0 z-20 transition-colors duration-200">
            <div className="flex items-center justify-between h-16 px-4 lg:px-6">
                <div className="flex items-center gap-3">
                    <button
                        onClick={onToggleSidebar}
                        className="lg:hidden text-gray-500 hover:text-gray-700 dark:text-slate-400 dark:hover:text-slate-200 p-2 hover:bg-gray-100 dark:hover:bg-slate-700 rounded-lg transition-colors"
                    >
                        <Menu size={20} />
                    </button>

                    {/* Search Bar - Hidden on small mobile */}
                    <div className="hidden md:flex items-center w-full max-w-md ml-2">
                        <div className="relative w-64 lg:w-80 transition-all focus-within:w-full">
                            <span className="absolute inset-y-0 left-0 flex items-center pl-3 pointer-events-none">
                                <Search className="w-4 h-4 text-gray-400" />
                            </span>
                            <input
                                type="text"
                                className="w-full py-2 pl-10 pr-4 text-sm bg-gray-50 dark:bg-slate-900 border border-gray-200 dark:border-slate-700 rounded-xl focus:outline-none focus:ring-2 focus:ring-primary/20 focus:border-primary transition-all duration-200"
                                placeholder="Search..."
                            />
                        </div>
                    </div>
                </div>

                <div className="flex items-center gap-2">
                    {/* Theme Toggle */}
                    <button
                        onClick={toggleTheme}
                        className="p-2 text-gray-500 dark:text-slate-400 hover:bg-gray-100 dark:hover:bg-slate-700 rounded-lg transition-colors"
                        title={isDark ? "Switch to Light Mode" : "Switch to Dark Mode"}
                    >
                        {isDark ? <Sun className="w-5 h-5" /> : <Moon className="w-5 h-5" />}
                    </button>

                    {/* Notifications */}
                    <div className="relative">
                        <button
                            onClick={() => setIsNotificationsOpen(!isNotificationsOpen)}
                            className="relative p-2 text-gray-500 dark:text-slate-400 hover:bg-gray-100 dark:hover:bg-slate-700 rounded-lg transition-colors"
                        >
                            <Bell className="w-5 h-5" />
                            <span className="absolute top-1.5 right-1.5 w-2 h-2 bg-red-500 rounded-full ring-2 ring-white dark:ring-slate-800 animate-pulse"></span>
                        </button>

                        {isNotificationsOpen && (
                            <div className="absolute right-0 mt-2 w-80 bg-white dark:bg-slate-800 rounded-xl shadow-xl border border-gray-100 dark:border-slate-700 py-2 z-50 transform origin-top-right transition-all animate-fade-in-down">
                                <div className="px-4 py-2 border-b border-gray-100 dark:border-slate-700 flex justify-between items-center bg-gray-50/50 dark:bg-slate-700/50 rounded-t-xl">
                                    <h3 className="font-semibold text-gray-900 dark:text-slate-100 text-sm">Notifications</h3>
                                    <button className="text-xs text-primary font-medium hover:text-primary-dark">
                                        Mark all read
                                    </button>
                                </div>
                                <div className="max-h-80 overflow-y-auto">
                                    {[
                                        { id: 1, text: 'New lab results for Sarah Johnson', time: '5m ago', unread: true },
                                        { id: 2, text: 'Appointment with Mike Ross cancelled', time: '1h ago', unread: true },
                                        { id: 3, text: 'System maintenance scheduled', time: '1d ago', unread: false },
                                    ].map((notif) => (
                                        <div
                                            key={notif.id}
                                            className={`px-4 py-3 hover:bg-gray-50 dark:hover:bg-slate-700/50 cursor-pointer border-b border-gray-50 dark:border-slate-700/50 last:border-0 ${notif.unread ? 'bg-blue-50/30 dark:bg-blue-900/10' : ''
                                                }`}
                                        >
                                            <p className="text-sm text-gray-800 dark:text-slate-200 font-medium">{notif.text}</p>
                                            <p className="text-xs text-gray-500 dark:text-slate-400 mt-1 flex items-center gap-1">
                                                <Clock className="w-3 h-3" />
                                                {notif.time}
                                            </p>
                                        </div>
                                    ))}
                                </div>
                                <div className="px-4 py-2 border-t border-gray-100 dark:border-slate-700 text-center bg-gray-50/50 dark:bg-slate-700/50 rounded-b-xl">
                                    <button className="text-sm text-gray-600 dark:text-slate-400 hover:text-primary dark:hover:text-primary font-medium transition-colors">
                                        View all notifications
                                    </button>
                                </div>
                            </div>
                        )}
                    </div>

                    {/* Profile Dropdown - Desktop */}
                    <div className="hidden md:block relative ml-2">
                        <button
                            onClick={() => setIsProfileOpen(!isProfileOpen)}
                            className="flex items-center gap-3 pl-2 pr-1 py-1 rounded-lg hover:bg-gray-100 dark:hover:bg-slate-700 transition-colors"
                        >
                            <div className="text-right hidden lg:block">
                                <p className="text-sm font-semibold text-gray-900 dark:text-white leading-none">{userName}</p>
                                <p className="text-xs text-gray-500 dark:text-slate-400 mt-1 capitalize">{role}</p>
                            </div>
                            <div className="w-8 h-8 rounded-full bg-gradient-to-tr from-primary to-primary-light flex items-center justify-center text-white text-sm font-bold shadow-sm ring-2 ring-white dark:ring-slate-800">
                                {userName.charAt(0)}
                            </div>
                            <ChevronDown className="w-4 h-4 text-gray-400" />
                        </button>

                        {isProfileOpen && (
                            <div className="absolute right-0 mt-2 w-56 bg-white dark:bg-slate-800 rounded-xl shadow-xl border border-gray-100 dark:border-slate-700 py-2 z-50 animate-fade-in-down">
                                <div className="px-4 py-3 border-b border-gray-100 dark:border-slate-700 mb-1 lg:hidden">
                                    <p className="font-semibold text-gray-900 dark:text-white">{userName}</p>
                                    <p className="text-xs text-gray-500 dark:text-slate-400 capitalize">{role}</p>
                                </div>
                                <button
                                    onClick={() => {
                                        navigate(`/dashboard/${role}/profile`);
                                        setIsProfileOpen(false);
                                    }}
                                    className="w-full text-left px-4 py-2 text-sm text-gray-700 dark:text-slate-300 hover:bg-gray-50 dark:hover:bg-slate-700/50 flex items-center gap-2 transition-colors"
                                >
                                    <Users className="w-4 h-4" /> Profile
                                </button>
                                <button className="w-full text-left px-4 py-2 text-sm text-gray-700 dark:text-slate-300 hover:bg-gray-50 dark:hover:bg-slate-700/50 flex items-center gap-2 transition-colors">
                                    <Shield className="w-4 h-4" /> Settings
                                </button>
                                <div className="border-t border-gray-100 dark:border-slate-700 mt-2 pt-2">
                                    <button
                                        onClick={onLogout}
                                        className="w-full text-left px-4 py-2 text-sm text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-900/20 flex items-center gap-2 font-medium transition-colors"
                                    >
                                        <LogOut className="w-4 h-4" /> Sign Out
                                    </button>
                                </div>
                            </div>
                        )}
                    </div>
                </div>
            </div>
        </header>
    );
};

export default Header;
