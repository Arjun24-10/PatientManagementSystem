import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import { Heart, Shield, Clock, Users, Mail, Lock, Eye, EyeOff, AlertCircle, CheckCircle, X } from 'lucide-react';
import { mockLogin } from '../mocks/auth';

export default function Login() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [rememberMe, setRememberMe] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [loading, setLoading] = useState(false);
  const [fieldErrors, setFieldErrors] = useState({ email: '', password: '' });

  const navigate = useNavigate();
  const { login } = useAuth();

  // Load remembered email on mount
  useEffect(() => {
    const rememberedEmail = localStorage.getItem('rememberedEmail');
    const wasRemembered = localStorage.getItem('rememberMe') === 'true';
    if (rememberedEmail && wasRemembered) {
      setEmail(rememberedEmail);
      setRememberMe(true);
    }
  }, []);

  // Real-time field validation
  const validateField = (field, value) => {
    const errors = { ...fieldErrors };
    
    if (field === 'email') {
      if (!value) {
        errors.email = 'Email is required';
      } else if (!value.includes('@') && !/^[a-zA-Z0-9_]+$/.test(value)) {
        errors.email = 'Please enter a valid email or username';
      } else {
        errors.email = '';
      }
    }
    
    if (field === 'password') {
      if (!value) {
        errors.password = 'Password is required';
      } else if (value.length < 6) {
        errors.password = 'Password must be at least 6 characters';
      } else {
        errors.password = '';
      }
    }
    
    setFieldErrors(errors);
    return !errors.email && !errors.password;
  };

  const handleEmailBlur = () => validateField('email', email);
  const handlePasswordBlur = () => validateField('password', password);

  const dismissError = () => setError('');
  // eslint-disable-next-line no-unused-vars
  const dismissSuccess = () => setSuccess('');

  const handleLogin = async (e) => {
    e.preventDefault();
    setError('');
    setSuccess('');
    
    // Validate all fields
    const emailValid = validateField('email', email);
    const passwordValid = validateField('password', password);
    
    if (!email || !password) {
      setError('Please enter email and password');
      return;
    }
    
    if (!emailValid || !passwordValid) {
      return;
    }

    setLoading(true);

    try {
      // First try mock authentication (for demo/dev)
      const mockResult = await mockLogin(email, password, rememberMe);
      
      if (mockResult.success) {
        // Handle remember me
        if (rememberMe) {
          localStorage.setItem('rememberMe', 'true');
          localStorage.setItem('rememberedEmail', email);
        } else {
          localStorage.removeItem('rememberMe');
          localStorage.removeItem('rememberedEmail');
        }

        // Check if 2FA is required
        if (mockResult.requiresTwoFactor) {
          // Store temp data and redirect to 2FA page
          sessionStorage.setItem('2fa_temp_token', mockResult.tempToken);
          sessionStorage.setItem('2fa_user', JSON.stringify(mockResult.user));
          setSuccess('Credentials verified! Redirecting to verification...');
          setTimeout(() => {
            navigate('/verify-2fa');
          }, 1000);
          return;
        }

        // Direct login success
        setSuccess('Login successful! Redirecting...');
        setTimeout(() => {
          navigate(mockResult.redirectTo);
        }, 1000);
        return;
      }

      // If mock auth fails, try real backend
      const result = await login(email, password);

      if (result.success) {
        if (rememberMe) {
          localStorage.setItem('rememberMe', 'true');
          localStorage.setItem('rememberedEmail', email);
        } else {
          localStorage.removeItem('rememberMe');
          localStorage.removeItem('rememberedEmail');
        }

        const userRole = (result.user?.role || result.user?.user_metadata?.role || 'PATIENT').toLowerCase();
        const dashboardPath = `/dashboard/${userRole}`;
        
        setSuccess('Login successful! Redirecting...');
        setTimeout(() => {
          navigate(dashboardPath);
        }, 1000);
      } else {
        setError(result.error || mockResult.error || 'Login failed. Please check your credentials and try again.');
        setLoading(false);
      }
    } catch (err) {
      setError('Network error. Please check your connection and try again.');
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen relative overflow-hidden bg-gradient-to-br from-blue-50 via-purple-50 to-cyan-50 dark:from-slate-900 dark:via-slate-800 dark:to-slate-900">
      {/* Animated Background Gradients */}
      <div className="absolute top-0 left-0 w-full h-full">
        <div className="absolute top-0 left-0 w-96 h-96 bg-blue-400 rounded-full mix-blend-multiply filter blur-3xl opacity-20 animate-float"></div>
        <div className="absolute top-0 right-0 w-96 h-96 bg-purple-400 rounded-full mix-blend-multiply filter blur-3xl opacity-20 animate-float" style={{ animationDelay: '2s' }}></div>
        <div className="absolute bottom-0 left-1/2 w-96 h-96 bg-cyan-400 rounded-full mix-blend-multiply filter blur-3xl opacity-20 animate-float" style={{ animationDelay: '4s' }}></div>
      </div>

      <div className="relative z-10 flex min-h-screen items-center justify-center p-4">
        <div className="w-full max-w-4xl">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-8 items-center">

          {/* Left Panel - Branding */}
          <div className="hidden lg:block space-y-8 animate-fade-in">
            <div className="space-y-4">
              <div className="inline-flex items-center gap-2 px-4 py-2 bg-white/50 dark:bg-slate-800/50 backdrop-blur-sm rounded-full border border-white/20 dark:border-slate-700/50">
                <Heart className="w-5 h-5 text-blue-600 dark:text-blue-400" />
                <span className="text-sm font-semibold text-gray-700 dark:text-slate-200">Premium Healthcare Platform</span>
              </div>

              <h1 className="text-5xl font-bold leading-tight">
                <span className="bg-gradient-to-r from-blue-600 to-purple-600 bg-clip-text text-transparent">
                  Expert Care,
                </span>
                <br />
                <span className="text-gray-800 dark:text-slate-100">Always Available</span>
              </h1>

              <p className="text-lg text-gray-600 dark:text-slate-400 max-w-md">
                Join thousands of patients experiencing world-class healthcare with our dedicated team of specialists.
              </p>
            </div>

            {/* Stats Cards */}
            <div className="grid grid-cols-2 gap-4">
              <div className="glass-card dark:bg-slate-800/50 dark:border-slate-700/50 p-6 rounded-2xl hover-lift animate-fade-in-delay-1">
                <div className="flex items-center gap-3 mb-2">
                  <div className="p-2 bg-gradient-to-br from-blue-500 to-blue-600 rounded-xl">
                    <Users className="w-5 h-5 text-white" />
                  </div>
                  <p className="text-2xl font-bold bg-gradient-to-r from-blue-600 to-blue-700 bg-clip-text text-transparent">5000+</p>
                </div>
                <p className="text-sm text-gray-600 dark:text-slate-400 font-medium">Verified Doctors</p>
              </div>

              <div className="glass-card dark:bg-slate-800/50 dark:border-slate-700/50 p-6 rounded-2xl hover-lift animate-fade-in-delay-2">
                <div className="flex items-center gap-3 mb-2">
                  <div className="p-2 bg-gradient-to-br from-purple-500 to-purple-600 rounded-xl">
                    <Clock className="w-5 h-5 text-white" />
                  </div>
                  <p className="text-2xl font-bold bg-gradient-to-r from-purple-600 to-purple-700 bg-clip-text text-transparent">24/7</p>
                </div>
                <p className="text-sm text-gray-600 dark:text-slate-400 font-medium">Available Care</p>
              </div>

              <div className="glass-card dark:bg-slate-800/50 dark:border-slate-700/50 p-6 rounded-2xl hover-lift animate-fade-in-delay-3">
                <div className="flex items-center gap-3 mb-2">
                  <div className="p-2 bg-gradient-to-br from-cyan-500 to-cyan-600 rounded-xl">
                    <Shield className="w-5 h-5 text-white" />
                  </div>
                  <p className="text-2xl font-bold bg-gradient-to-r from-cyan-600 to-cyan-700 bg-clip-text text-transparent">100%</p>
                </div>
                <p className="text-sm text-gray-600 dark:text-slate-400 font-medium">HIPAA Secure</p>
              </div>

              <div className="glass-card dark:bg-slate-800/50 dark:border-slate-700/50 p-6 rounded-2xl hover-lift animate-fade-in-delay-4">
                <div className="flex items-center gap-3 mb-2">
                  <div className="p-2 bg-gradient-to-br from-green-500 to-green-600 rounded-xl">
                    <Heart className="w-5 h-5 text-white" />
                  </div>
                  <p className="text-2xl font-bold bg-gradient-to-r from-green-600 to-green-700 bg-clip-text text-transparent">98%</p>
                </div>
                <p className="text-sm text-gray-600 dark:text-slate-400 font-medium">Satisfaction Rate</p>
              </div>
            </div>
          </div>

          {/* Right Panel - Login Form */}
          <div className="glass-card dark:bg-slate-800/80 dark:border-slate-700/50 p-8 md:p-10 rounded-3xl animate-fade-in-delay-1 relative z-20">
            <div className="space-y-6 relative z-20">
              <div className="space-y-2">
                <h2 className="text-3xl font-bold text-gray-900 dark:text-slate-100">Welcome Back</h2>
                <p className="text-gray-600 dark:text-slate-400">Sign in to access your healthcare dashboard</p>
              </div>

              <form onSubmit={handleLogin} className="space-y-5 relative z-20">
                <div className="space-y-2">
                  <label htmlFor="email" className="block text-sm font-semibold text-gray-700 dark:text-slate-200">
                    Email or Username
                  </label>
                  <div className="relative">
                    <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                      <Mail className="h-5 w-5 text-gray-400 dark:text-slate-500" />
                    </div>
                    <input
                      type="text"
                      id="email"
                      className={`w-full border-2 rounded-xl pl-10 pr-4 py-3 focus:outline-none focus:ring-2 transition-all bg-white dark:bg-slate-800 text-gray-900 dark:text-slate-100 placeholder-gray-500 dark:placeholder-slate-500 ${
                        fieldErrors.email 
                          ? 'border-red-300 dark:border-red-500 focus:ring-red-500 focus:border-red-500' 
                          : 'border-gray-300 dark:border-slate-600 focus:ring-blue-500 focus:border-blue-500'
                      }`}
                      placeholder="Enter your email or username"
                      value={email}
                      onChange={(e) => setEmail(e.target.value)}
                      onBlur={handleEmailBlur}
                      aria-describedby={fieldErrors.email ? 'email-error' : undefined}
                      required
                    />
                  </div>
                  {fieldErrors.email && (
                    <p id="email-error" className="text-sm text-red-600 dark:text-red-400 flex items-center gap-1">
                      <AlertCircle className="h-4 w-4" />
                      {fieldErrors.email}
                    </p>
                  )}
                </div>

                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <label htmlFor="password" className="block text-sm font-semibold text-gray-700 dark:text-slate-200">
                      Password
                    </label>
                    <button 
                      type="button" 
                      onClick={() => navigate('/forgot-password')}
                      className="text-sm text-blue-600 dark:text-blue-400 hover:text-blue-700 dark:hover:text-blue-300 font-medium transition-colors"
                    >
                      Forgot?
                    </button>
                  </div>
                  <div className="relative">
                    <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                      <Lock className="h-5 w-5 text-gray-400 dark:text-slate-500" />
                    </div>
                    <input
                      type={showPassword ? 'text' : 'password'}
                      id="password"
                      className={`w-full border-2 rounded-xl pl-10 pr-12 py-3 focus:outline-none focus:ring-2 transition-all bg-white dark:bg-slate-800 text-gray-900 dark:text-slate-100 placeholder-gray-500 dark:placeholder-slate-500 ${
                        fieldErrors.password 
                          ? 'border-red-300 dark:border-red-500 focus:ring-red-500 focus:border-red-500' 
                          : 'border-gray-300 dark:border-slate-600 focus:ring-blue-500 focus:border-blue-500'
                      }`}
                      placeholder="Enter your password"
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      onBlur={handlePasswordBlur}
                      aria-describedby={fieldErrors.password ? 'password-error' : undefined}
                      required
                    />
                    <button
                      type="button"
                      className="absolute inset-y-0 right-0 pr-3 flex items-center text-gray-400 dark:text-slate-500 hover:text-gray-600 dark:hover:text-slate-300 transition-colors"
                      onClick={() => setShowPassword(!showPassword)}
                      aria-label={showPassword ? 'Hide password' : 'Show password'}
                    >
                      {showPassword ? <EyeOff className="h-5 w-5" /> : <Eye className="h-5 w-5" />}
                    </button>
                  </div>
                  {fieldErrors.password && (
                    <p id="password-error" className="text-sm text-red-600 dark:text-red-400 flex items-center gap-1">
                      <AlertCircle className="h-4 w-4" />
                      {fieldErrors.password}
                    </p>
                  )}
                </div>

                <div className="flex items-center">
                  <input
                    type="checkbox"
                    id="rememberMe"
                    className="w-4 h-4 text-blue-600 border-2 border-gray-300 dark:border-slate-600 rounded focus:ring-2 focus:ring-blue-500 cursor-pointer dark:bg-slate-800"
                    checked={rememberMe}
                    onChange={(e) => setRememberMe(e.target.checked)}
                  />
                  <label htmlFor="rememberMe" className="ml-2 text-sm font-medium text-gray-700 dark:text-slate-300 cursor-pointer">
                    Remember me
                  </label>
                </div>

                {/* Error Alert */}
                {error && (
                  <div className="bg-gradient-to-r from-red-50 to-red-100 dark:from-red-900/30 dark:to-red-800/30 border border-red-200 dark:border-red-800 text-red-700 dark:text-red-300 px-4 py-3 rounded-xl text-sm font-medium flex items-center justify-between animate-shake">
                    <div className="flex items-center gap-2">
                      <AlertCircle className="h-5 w-5 text-red-500" />
                      <span>{error}</span>
                    </div>
                    <button 
                      type="button" 
                      onClick={dismissError}
                      className="text-red-500 dark:text-red-400 hover:text-red-700 dark:hover:text-red-300 transition-colors"
                      aria-label="Dismiss error"
                    >
                      <X className="h-4 w-4" />
                    </button>
                  </div>
                )}

                {/* Success Alert */}
                {success && (
                  <div className="bg-gradient-to-r from-green-50 to-green-100 dark:from-green-900/30 dark:to-green-800/30 border border-green-200 dark:border-green-800 text-green-700 dark:text-green-300 px-4 py-3 rounded-xl text-sm font-medium flex items-center gap-2">
                    <CheckCircle className="h-5 w-5 text-green-500" />
                    <span>{success}</span>
                  </div>
                )}

                <button
                  type="submit"
                  className="w-full bg-gradient-to-r from-blue-600 to-purple-600 text-white py-3 rounded-xl font-semibold hover:shadow-xl hover:-translate-y-0.5 transition-all duration-200 disabled:opacity-50 disabled:cursor-not-allowed disabled:transform-none"
                  disabled={loading}
                >
                  {loading ? (
                    <span className="flex items-center justify-center gap-2">
                      <svg className="animate-spin h-5 w-5 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                        <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                        <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                      </svg>
                      Signing In...
                    </span>
                  ) : (
                    'Sign In'
                  )}
                </button>

                <div className="relative my-6">
                  <div className="absolute inset-0 flex items-center">
                    <div className="w-full border-t border-gray-300 dark:border-slate-600"></div>
                  </div>
                  <div className="relative flex justify-center text-sm">
                    <span className="px-4 bg-white dark:bg-slate-800 text-gray-500 dark:text-slate-400 font-medium">Don't have an account?</span>
                  </div>
                </div>

                <button
                  type="button"
                  className="w-full bg-gradient-to-r from-blue-50 to-blue-100 dark:from-blue-900/30 dark:to-blue-800/30 text-blue-700 dark:text-blue-300 py-3 rounded-xl font-semibold border-2 border-blue-200 dark:border-blue-700 hover:border-blue-300 dark:hover:border-blue-600 hover:shadow-md transition-all duration-200"
                  onClick={() => navigate('/create')}
                >
                  Create Account
                </button>
              </form>

              <p className="text-center text-xs text-gray-500 dark:text-slate-400 mt-6">
                By signing in, you agree to our{' '}
                <button className="text-blue-600 dark:text-blue-400 hover:text-blue-700 dark:hover:text-blue-300 font-medium">Terms of Service</button>
                {' '}and{' '}
                <button className="text-blue-600 dark:text-blue-400 hover:text-blue-700 dark:hover:text-blue-300 font-medium">Privacy Policy</button>
              </p>

              {/* Footer Links */}
              <div className="pt-4 border-t border-gray-200 dark:border-slate-700 mt-6">
                <div className="flex items-center justify-center gap-4 text-xs text-gray-500 dark:text-slate-400">
                  <button className="hover:text-blue-600 dark:hover:text-blue-400 transition-colors">Privacy Policy</button>
                  <span>•</span>
                  <button className="hover:text-blue-600 dark:hover:text-blue-400 transition-colors">Terms of Service</button>
                  <span>•</span>
                  <button className="hover:text-blue-600 dark:hover:text-blue-400 transition-colors">Help</button>
                </div>
                <p className="text-center text-xs text-gray-400 dark:text-slate-500 mt-3">
                  © 2026 Healthcare Management System. All rights reserved.
                </p>
              </div>
            </div>
          </div>
          </div>
        </div>
      </div>
    </div>
  );
}