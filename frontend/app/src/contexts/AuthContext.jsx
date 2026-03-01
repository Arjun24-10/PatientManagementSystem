import React, { createContext, useState, useEffect, useRef } from 'react';
import * as authService from '../services/supabaseAuth';

export const AuthContext = createContext();

// Decode JWT exp claim without a library (standard base64 decode)
const getTokenExpiry = (token) => {
  try {
    const payload = JSON.parse(atob(token.split('.')[1]));
    return payload.exp ? payload.exp * 1000 : null; // convert to ms
  } catch {
    return null;
  }
};

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [session, setSession] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const logoutTimerRef = useRef(null);

  // Schedule automatic logout when the JWT expires
  const scheduleAutoLogout = (token) => {
    // Clear any existing timer
    if (logoutTimerRef.current) clearTimeout(logoutTimerRef.current);

    const expiresAt = getTokenExpiry(token);
    if (!expiresAt) return;

    const msUntilExpiry = expiresAt - Date.now();
    if (msUntilExpiry <= 0) {
      // Already expired — logout immediately
      performLogout();
      return;
    }

    logoutTimerRef.current = setTimeout(() => {
      console.warn('Session expired. Logging out automatically.');
      performLogout();
    }, msUntilExpiry);
  };

  const performLogout = () => {
    localStorage.removeItem('secure_health_user');
    setUser(null);
    setSession(null);
    window.location.href = '/login';
  };

  // Initialize auth state on mount
  useEffect(() => {
    const initializeAuth = async () => {
      try {
        const currentSession = await authService.getCurrentSession();
        setSession(currentSession);
        if (currentSession) {
          const token = currentSession.user?.accessToken;
          // If token is already expired, don't restore session
          if (token && getTokenExpiry(token) <= Date.now()) {
            localStorage.removeItem('secure_health_user');
            setLoading(false);
            return;
          }
          setUser(currentSession.user);
          if (token) scheduleAutoLogout(token);
        }
      } catch (err) {
        setError(err.message);
      } finally {
        setLoading(false);
      }
    };

    initializeAuth();

    // Listen to auth state changes
    const unsubscribe = authService.onAuthStateChange((newSession) => {
      setSession(newSession);
      setUser(newSession?.user || null);
      if (newSession?.user?.accessToken) {
        scheduleAutoLogout(newSession.user.accessToken);
      }
    });

    return () => {
      unsubscribe();
      if (logoutTimerRef.current) clearTimeout(logoutTimerRef.current);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const login = async (email, password) => {
    setError(null);
    setLoading(true);
    try {
      const result = await authService.signIn(email, password);
      if (result.status === 'OTP_REQUIRED') {
        return { success: false, status: 'OTP_REQUIRED' };
      }
      if (result.success) {
        setUser(result.user);
        setSession(result.session);
        // Schedule auto-logout based on JWT expiry
        if (result.user?.accessToken) {
          scheduleAutoLogout(result.user.accessToken);
        }
        return { success: true, status: result.status };
      } else {
        setError(result.error);
        return { success: false, error: result.error };
      }
    } catch (err) {
      setError(err.message);
      return { success: false, error: err.message };
    } finally {
      setLoading(false);
    }
  };

  const signup = async (email, password, userData) => {
    setError(null);
    setLoading(true);
    try {
      const result = await authService.signUp(email, password, userData);
      if (result.success) {
        setUser(result.user);
        setSession(result.session);
        return { success: true };
      } else {
        setError(result.error);
        return { success: false, error: result.error };
      }
    } catch (err) {
      setError(err.message);
      return { success: false, error: err.message };
    } finally {
      setLoading(false);
    }
  };

  const logout = async () => {
    setError(null);
    if (logoutTimerRef.current) clearTimeout(logoutTimerRef.current);
    try {
      const result = await authService.signOut();
      if (result.success) {
        setUser(null);
        setSession(null);
        return { success: true };
      } else {
        setError(result.error);
        return { success: false, error: result.error };
      }
    } catch (err) {
      setError(err.message);
      return { success: false, error: err.message };
    }
  };

  const value = {
    user,
    session,
    loading,
    error,
    login,
    signup,
    logout,
    isAuthenticated: !!user,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};

// Custom hook to use auth context
export const useAuth = () => {
  const context = React.useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};
