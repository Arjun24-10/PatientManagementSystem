import React from 'react';
import { Navigate, useLocation, Outlet } from 'react-router-dom';
import { useAuth } from '../../contexts/AuthContext';

const ProtectedRoute = ({ allowedRoles = [], children }) => {
    const { user, loading } = useAuth();
    const location = useLocation();

    if (loading) {
        // You might want a better loading spinner here
        return (
            <div className="flex items-center justify-center min-h-screen bg-gray-50 dark:bg-slate-900">
                <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-blue-500"></div>
            </div>
        );
    }

    if (!user) {
        // Redirect to login page with the return url
        return <Navigate to="/login" state={{ from: location }} replace />;
    }

    // Role check
    // Ensure role comparison is case-insensitive and robust
    const userRole = (user.role || user.user_metadata?.role || '').toLowerCase();

    if (allowedRoles.length > 0) {
        const hasPermission = allowedRoles.some(role => role.toLowerCase() === userRole);
        if (!hasPermission) {
            return <Navigate to="/unauthorized" replace />;
        }
    }

    return children ? children : <Outlet />;
};

export default ProtectedRoute;
