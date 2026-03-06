// Authentication service for backend API
const API_BASE_URL = 'http://localhost:8081/api';
const AUTH_URL = `${API_BASE_URL}/auth`;
const STORAGE_KEY = 'secure_health_user';
const PROFILE_STORAGE_KEY = 'secure_health_profiles';

const fetchWithTimeout = async (url, options = {}, timeoutMs = 12000) => {
   const controller = new AbortController();
   const id = setTimeout(() => controller.abort(), timeoutMs);
   try {
      const response = await fetch(url, { credentials: 'include', ...options, signal: controller.signal });
      clearTimeout(id);
      return response;
   } catch (err) {
      clearTimeout(id);
      if (err?.name === 'AbortError') {
         throw new Error('Request timed out');
      }
      if (typeof err?.message === 'string' && err.message.includes('Failed to fetch')) {
         throw new Error('Network error. Please check your connection.');
      }
      throw err;
   }
};

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
   if (!data) return null;
   const user = JSON.parse(data);
   
   // If userId is missing but we have a token, extract it from JWT
   if (!user.userId && user.accessToken) {
      try {
         const parts = user.accessToken.split('.');
         if (parts.length === 3) {
            const payload = JSON.parse(atob(parts[1]));
            if (payload.userId) {
               user.userId = payload.userId;
               // Update localStorage with extracted userId
               saveSession(user);
            }
         }
      } catch (e) {
         console.warn('Failed to extract userId from JWT token');
      }
   }
   
   return user;
};

const getProfiles = () => {
   const data = localStorage.getItem(PROFILE_STORAGE_KEY);
   return data ? JSON.parse(data) : {};
};

const saveProfileName = (email, fullName) => {
   if (!email || !fullName) {
      return;
   }
   const profiles = getProfiles();
   profiles[email] = fullName;
   localStorage.setItem(PROFILE_STORAGE_KEY, JSON.stringify(profiles));
};

const getProfileName = (email) => {
   if (!email) {
      return null;
   }
   const profiles = getProfiles();
   return profiles[email] || null;
};

export const signup = async (email, password, userData = {}) => {
   try {
      const role = userData.role || 'PATIENT';
      const body = { email, password, role, ...userData };

      const response = await fetchWithTimeout(`${AUTH_URL}/register`, {
         method: 'POST',
         headers: { 'Content-Type': 'application/json' },
         body: JSON.stringify(body),
      });

      let data = {};
      const contentType = response.headers.get('content-type');
      if (contentType && contentType.includes('application/json')) {
         try {
            data = await response.json();
         } catch (e) {
            console.warn('Failed to parse response as JSON:', e);
            data = {};
         }
      }

      if (!response.ok) {
         throw new Error(data.message || 'Registration failed');
      }

      // Backend returns success message but no user object for register
      // We auto-login or ask user to login. Here we'll simulate auto-login for UX
      const fullName = userData.full_name || userData.fullName;
      const user = { email, role, fullName };
      if (fullName) {
         saveProfileName(email, fullName);
      }
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
      const result = await signup(email, password, userData);
      // Construct session object matching what AuthContext expects
      const session = { user: result.user };
      return { success: true, user: result.user, session };
   } catch (error) {
      return { success: false, error: error.message };
   }
};

export const login = async (email, password) => {
   try {
      const response = await fetchWithTimeout(`${AUTH_URL}/login`, {
         method: 'POST',
         headers: { 'Content-Type': 'application/json' },
         body: JSON.stringify({ email, password }),
      });

      let data = {};
      const contentType = response.headers.get('content-type');
      
      if (contentType && contentType.includes('application/json')) {
         try {
            const responseText = await response.text();
            data = JSON.parse(responseText);
         } catch (e) {
            console.warn('Failed to parse response as JSON:', e);
            data = {};
         }
      }

      if (!response.ok) {
         throw new Error(data.message || 'Login failed');
      }

      const status = data.status || data.message || 'LOGIN_SUCCESS';
      const resolvedEmail = data.email || email;
      const storedName = getProfileName(resolvedEmail);
      const fullName = data.full_name || data.fullName || storedName;

      const accessToken = data.accessToken || null;
      
      // Extract role EARLY - needed for fallback logic below
      const roleFromResponse = data.role || 'PATIENT';
      
      // CRITICAL: Get userId from response body (backend returns it in LoginResponse DTO)
      let userId = data.userId || null;
      
      // Fallback: try to parse from JWT token if not in response body
      if (!userId && accessToken) {
         try {
            const parts = accessToken.split('.');
            if (parts.length === 3) {
               const payload = JSON.parse(atob(parts[1]));
               userId = payload.userId || payload.sub;
            }
         } catch (e) {
            console.error('Failed to parse JWT token:', e);
         }
      }

      // Fallback: If still no userId, fetch from /patients/me or /doctors/{email} endpoint
      if (!userId && accessToken && roleFromResponse) {
         try {
            const headers = {
               'Content-Type': 'application/json',
               'Authorization': `Bearer ${accessToken}`
            };
            
            // Try to get profile based on role
            let profileUrl = `${API_BASE_URL}/patients/me`;
            if (roleFromResponse === 'DOCTOR' || roleFromResponse === 'NURSE' || roleFromResponse === 'ADMIN' || roleFromResponse === 'LAB_TECHNICIAN') {
               profileUrl = `${API_BASE_URL}/doctors/${email}`;
            }
            
            const profileResponse = await fetch(profileUrl, { headers, credentials: 'include' });
            if (profileResponse.ok) {
               const profileData = await profileResponse.json();
               userId = profileData.userId || profileData.id || profileData.user_id;
            }
         } catch (e) {
            console.error('Failed to fetch profile:', e);
         }
      }
      
      const user = { email: resolvedEmail, role: roleFromResponse, fullName, accessToken, userId };
      if (status === 'OTP_REQUIRED') {
         return { status, user };
      }
      if (fullName) {
         saveProfileName(resolvedEmail, fullName);
      }
      saveSession(user);
      console.log('✓ Login successful - User stored:', user);
      return { status, user, ...data };
   } catch (error) {
      throw error;
   }
};

export const signIn = async (email, password) => {
   try {
      const result = await login(email, password);
      if (result.status === 'OTP_REQUIRED') {
         return { success: false, status: 'OTP_REQUIRED', user: result.user };
      }
      const session = { user: result.user };
      return { success: true, user: result.user, session, status: result.status };
   } catch (error) {
      return { success: false, error: error.message };
   }
};

export const logout = async () => {
   try {
      const userSession = getSession();
      const headers = { 'Content-Type': 'application/json' };
      if (userSession && userSession.accessToken) {
         headers['Authorization'] = `Bearer ${userSession.accessToken}`;
      }
      await fetchWithTimeout(`${AUTH_URL}/logout`, { method: 'POST', headers });
   } catch (e) {
      // Ignore network errors; still clear local session
   } finally {
      clearSession();
      return { message: 'Logged out successfully' };
   }
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

// Password Recovery Functions

// Request password reset email
export const forgotPassword = async (email) => {
   try {
      const response = await fetchWithTimeout(`${AUTH_URL}/forgot-password`, {
         method: 'POST',
         headers: {
            'Content-Type': 'application/json',
         },
         body: JSON.stringify({ email }),
      });

      let data = {};
      const contentType = response.headers.get('content-type');
      if (contentType && contentType.includes('application/json')) {
         try {
            data = await response.json();
         } catch (e) {
            console.warn('Failed to parse response as JSON:', e);
            data = {};
         }
      }

      if (response.ok) {
         return { success: true, message: data.message || 'Password reset email sent successfully' };
      } else {
         return { success: false, error: data.error || 'Failed to send password reset email' };
      }
   } catch (error) {
      console.error('Forgot password error:', error);
      return { success: false, error: 'Network error. Please try again.' };
   }
};

// Validate password reset token
export const validateResetToken = async (token) => {
   try {
      const response = await fetchWithTimeout(`${AUTH_URL}/validate-reset-token?token=${encodeURIComponent(token)}`, {
         method: 'GET',
         headers: {
            'Content-Type': 'application/json',
         },
      });

      let data = {};
      const contentType = response.headers.get('content-type');
      if (contentType && contentType.includes('application/json')) {
         try {
            data = await response.json();
         } catch (e) {
            console.warn('Failed to parse response as JSON:', e);
            data = {};
         }
      }

      if (response.ok) {
         return { valid: true, message: data.message };
      } else {
         return { valid: false, error: data.error || 'Invalid or expired token' };
      }
   } catch (error) {
      console.error('Validate token error:', error);
      return { valid: false, error: 'Network error. Please try again.' };
   }
};

// Reset password with token
export const resetPassword = async (token, newPassword, confirmPassword) => {
   try {
      const response = await fetchWithTimeout(`${AUTH_URL}/reset-password`, {
         method: 'POST',
         headers: {
            'Content-Type': 'application/json',
         },
         body: JSON.stringify({ token, newPassword, confirmPassword }),
      });

      let data = {};
      const contentType = response.headers.get('content-type');
      if (contentType && contentType.includes('application/json')) {
         try {
            data = await response.json();
         } catch (e) {
            console.warn('Failed to parse response as JSON:', e);
            data = {};
         }
      }

      if (response.ok) {
         return { success: true, message: data.message || 'Password reset successfully' };
      } else {
         return { success: false, error: data.error || 'Failed to reset password' };
      }
   } catch (error) {
      console.error('Reset password error:', error);
      return { success: false, error: 'Network error. Please try again.' };
   }
};

// Verify OTP for 2FA
export const verifyOtp = async (email, otp) => {
   try {
      const response = await fetchWithTimeout(`${AUTH_URL}/verify-otp`, {
         method: 'POST',
         headers: { 'Content-Type': 'application/json' },
         body: JSON.stringify({ email, otp }),
      });

      // Check if response has content before parsing JSON
      let data = {};
      const contentType = response.headers.get('content-type');
      if (contentType && contentType.includes('application/json')) {
         try {
            data = await response.json();
         } catch (e) {
            console.warn('Failed to parse response as JSON:', e);
            data = {};
         }
      }

      if (response.ok) {
         const resolvedEmail = email;
         const storedName = getProfileName(resolvedEmail);
         const fullName = data.full_name || data.fullName || storedName;
         
         // Extract userId from response (CRITICAL FIX for OTP flow)
         let userId = data.userId || null;
         console.log('✓ userId from OTP response.userId:', userId);
         
         // Fallback: try to parse from JWT token if not in response body
         const accessToken = data.accessToken;
         if (!userId && accessToken) {
            try {
               const parts = accessToken.split('.');
               if (parts.length === 3) {
                  const payload = JSON.parse(atob(parts[1]));
                  console.log('✓ OTP Verify - JWT Payload:', payload);
                  userId = payload.userId || payload.sub;
                  console.log('✓ OTP userId from JWT:', userId);
               }
            } catch (e) {
               console.error('✗ OTP Verify - Failed to parse JWT token:', e);
            }
         }
         
         console.log('✓ OTP Verify Final - userId:', userId);
         const user = { email: resolvedEmail, role: data.role || 'PATIENT', fullName, accessToken, userId };
         if (fullName) {
            saveProfileName(resolvedEmail, fullName);
         }
         saveSession(user);
         return { success: true, user, ...data };
      } else {
         // Better error messages for different status codes
         if (response.status === 401) {
            return { success: false, error: 'Invalid or expired OTP. Please try again.' };
         } else if (response.status === 400) {
            return { success: false, error: data.message || 'Invalid OTP format. Please check and try again.' };
         } else {
            return { success: false, error: data.message || 'OTP verification failed. Please try again.' };
         }
      }
   } catch (error) {
      console.error('Verify OTP error:', error);
      return { success: false, error: 'Network error. Please try again.' };
   }
};

// Resend OTP
export const resendOtp = async (email) => {
   try {
      const response = await fetchWithTimeout(`${AUTH_URL}/resend-otp`, {
         method: 'POST',
         headers: { 'Content-Type': 'application/json' },
         body: JSON.stringify({ email }),
      });
      const data = await response.json();
      if (response.ok) {
         return { success: true, message: data.message || 'OTP resent' };
      } else {
         return { success: false, error: data.message || 'Failed to resend OTP' };
      }
   } catch (error) {
      console.error('Resend OTP error:', error);
      return { success: false, error: 'Network error. Please try again.' };
   }
};
