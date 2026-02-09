// Authentication service for backend API
const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:8080/api';
const AUTH_URL = `${API_BASE_URL}/auth`;
const STORAGE_KEY = 'secure_health_user';

// Auth state change listeners
let authStateListeners = [];

const saveSession = (user) => {
   localStorage.setItem(STORAGE_KEY, JSON.stringify(user));
   notifyAuthStateChange({ user });
};

const clearSession = () => {
   localStorage.removeItem(STORAGE_KEY);
   notifyAuthStateChange(null);
};

const getSession = () => {
   const data = localStorage.getItem(STORAGE_KEY);
   return data ? JSON.parse(data) : null;
};

export const signup = async (email, password, role = 'PATIENT') => {
   try {
      const response = await fetch(`${AUTH_URL}/register`, {
         method: 'POST',
         headers: { 'Content-Type': 'application/json' },
         body: JSON.stringify({ email, password, role }),
      });

      if (!response.ok) {
         const error = await response.json().catch(() => ({}));
         throw new Error(error.message || 'Registration failed');
      }

      // Backend returns success message but no user object for register
      // We auto-login or ask user to login. Here we'll simulate auto-login for UX
      const user = { email, role };
      // Note: In a real app we might require login after register, 
      // but for "integration" we'll set session
      saveSession(user);

      return { message: 'User registered successfully', user };
   } catch (error) {
      throw error;
   }
};

export const signUp = async (email, password, userData) => {
   try {
      const role = userData?.role || 'PATIENT';
      const result = await signup(email, password, role);
      // Construct session object matching what AuthContext expects
      const session = { user: result.user };
      return { success: true, user: result.user, session };
   } catch (error) {
      return { success: false, error: error.message };
   }
};

export const login = async (email, password) => {
   try {
      const response = await fetch(`${AUTH_URL}/login`, {
         method: 'POST',
         headers: { 'Content-Type': 'application/json' },
         body: JSON.stringify({ email, password }),
      });

      if (!response.ok) {
         const error = await response.json().catch(() => ({}));
         throw new Error(error.message || 'Login failed');
      }

      let data = await response.json();
      // Expecting data to contain { message, email, role } based on backend
      const user = {
         email: data.email || email,
         role: data.role || 'PATIENT'
      };

      saveSession(user);
      return { user, ...data };
   } catch (error) {
      throw error;
   }
};

export const signIn = async (email, password) => {
   try {
      const result = await login(email, password);
      // Construct session object matching what AuthContext expects
      const session = { user: result.user };
      return { success: true, user: result.user, session };
   } catch (error) {
      return { success: false, error: error.message };
   }
};

export const logout = async () => {
   // Client-side logout only since backend has no logout endpoint
   clearSession();
   return { message: 'Logged out successfully' };
};

export const signOut = async () => {
   try {
      await logout();
      return { success: true };
   } catch (error) {
      return { success: false, error: error.message };
   }
};

export const getCurrentUser = async () => {
   // Return local session instead of calling API
   return getSession();
};

export const getCurrentSession = async () => {
   const user = getSession();
   return user ? { user } : null;
};

// Auth state change listener
export const onAuthStateChange = (callback) => {
   authStateListeners.push(callback);

   // Initialize with current state
   const currentSession = getSession();
   if (currentSession) {
      // callback({ user: currentSession }); 
      // Don't fire immediately to avoid render loops, 
      // AuthContext calls getCurrentSession on mount anyway.
   }

   // Return unsubscribe function
   return () => {
      authStateListeners = authStateListeners.filter(listener => listener !== callback);
   };
};

// Notify all listeners of auth state change
const notifyAuthStateChange = (session) => {
   authStateListeners.forEach(listener => listener(session));
};

