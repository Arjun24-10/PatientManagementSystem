import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import { Heart, Shield, Clock, Users } from 'lucide-react';

export default function Login() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [rememberMe, setRememberMe] = useState(false);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const navigate = useNavigate();
  const { login } = useAuth();

  const handleLogin = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    // Validation
    if (!email || !password) {
      setError('Please enter email and password');
      setLoading(false);
      return;
    }

    if (!email.includes('@')) {
      setError('Please enter a valid email address');
      setLoading(false);
      return;
    }

    // Attempt login
    const result = await login(email, password);

    if (result.success) {
      // Store remember me preference
      if (rememberMe) {
        localStorage.setItem('rememberMe', 'true');
        localStorage.setItem('rememberedEmail', email);
      } else {
        localStorage.removeItem('rememberMe');
        localStorage.removeItem('rememberedEmail');
      }

      // Determine role-based redirect
      const userRole = result.user?.user_metadata?.role || 'patient';
      const dashboardPath = `/dashboard/${userRole}`;
      navigate(dashboardPath);
    } else {
      // Login failed - show error
      setError(result.error || 'Login failed. Please check your credentials and try again.');
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen relative overflow-hidden bg-gradient-to-br from-blue-50 via-purple-50 to-cyan-50">
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
              <div className="inline-flex items-center gap-2 px-4 py-2 bg-white/50 backdrop-blur-sm rounded-full border border-white/20">
                <Heart className="w-5 h-5 text-blue-600" />
                <span className="text-sm font-semibold text-gray-700">Premium Healthcare Platform</span>
              </div>

              <h1 className="text-5xl font-bold leading-tight">
                <span className="bg-gradient-to-r from-blue-600 to-purple-600 bg-clip-text text-transparent">
                  Expert Care,
                </span>
                <br />
                <span className="text-gray-800">Always Available</span>
              </h1>

              <p className="text-lg text-gray-600 max-w-md">
                Join thousands of patients experiencing world-class healthcare with our dedicated team of specialists.
              </p>
            </div>

            {/* Stats Cards */}
            <div className="grid grid-cols-2 gap-4">
              <div className="glass-card p-6 rounded-2xl hover-lift animate-fade-in-delay-1">
                <div className="flex items-center gap-3 mb-2">
                  <div className="p-2 bg-gradient-to-br from-blue-500 to-blue-600 rounded-xl">
                    <Users className="w-5 h-5 text-white" />
                  </div>
                  <p className="text-2xl font-bold bg-gradient-to-r from-blue-600 to-blue-700 bg-clip-text text-transparent">5000+</p>
                </div>
                <p className="text-sm text-gray-600 font-medium">Verified Doctors</p>
              </div>

              <div className="glass-card p-6 rounded-2xl hover-lift animate-fade-in-delay-2">
                <div className="flex items-center gap-3 mb-2">
                  <div className="p-2 bg-gradient-to-br from-purple-500 to-purple-600 rounded-xl">
                    <Clock className="w-5 h-5 text-white" />
                  </div>
                  <p className="text-2xl font-bold bg-gradient-to-r from-purple-600 to-purple-700 bg-clip-text text-transparent">24/7</p>
                </div>
                <p className="text-sm text-gray-600 font-medium">Available Care</p>
              </div>

              <div className="glass-card p-6 rounded-2xl hover-lift animate-fade-in-delay-3">
                <div className="flex items-center gap-3 mb-2">
                  <div className="p-2 bg-gradient-to-br from-cyan-500 to-cyan-600 rounded-xl">
                    <Shield className="w-5 h-5 text-white" />
                  </div>
                  <p className="text-2xl font-bold bg-gradient-to-r from-cyan-600 to-cyan-700 bg-clip-text text-transparent">100%</p>
                </div>
                <p className="text-sm text-gray-600 font-medium">HIPAA Secure</p>
              </div>

              <div className="glass-card p-6 rounded-2xl hover-lift animate-fade-in-delay-4">
                <div className="flex items-center gap-3 mb-2">
                  <div className="p-2 bg-gradient-to-br from-green-500 to-green-600 rounded-xl">
                    <Heart className="w-5 h-5 text-white" />
                  </div>
                  <p className="text-2xl font-bold bg-gradient-to-r from-green-600 to-green-700 bg-clip-text text-transparent">98%</p>
                </div>
                <p className="text-sm text-gray-600 font-medium">Satisfaction Rate</p>
              </div>
            </div>
          </div>

          {/* Right Panel - Login Form */}
          <div className="glass-card p-8 md:p-10 rounded-3xl animate-fade-in-delay-1 relative z-20">
            <div className="space-y-6 relative z-20">
              <div className="space-y-2">
                <h2 className="text-3xl font-bold text-gray-900">Welcome Back</h2>
                <p className="text-gray-600">Sign in to access your healthcare dashboard</p>
              </div>

              <form onSubmit={handleLogin} className="space-y-5 relative z-20">
                <div className="space-y-2">
                  <label htmlFor="email" className="block text-sm font-semibold text-gray-700">
                    Email Address
                  </label>
                  <input
                    type="email"
                    id="email"
                    className="w-full border-2 border-gray-300 rounded-xl px-4 py-3 focus:outline-none focus:ring-2 focus:ring-blue-500 transition-all bg-white text-gray-900 placeholder-gray-500"
                    placeholder="you@example.com"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    required
                  />
                </div>

                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <label htmlFor="password" className="block text-sm font-semibold text-gray-700">
                      Password
                    </label>
                    <button type="button" className="text-sm text-blue-600 hover:text-blue-700 font-medium transition-colors">
                      Forgot?
                    </button>
                  </div>
                  <input
                    type="password"
                    id="password"
                    className="w-full border-2 border-gray-300 rounded-xl px-4 py-3 focus:outline-none focus:ring-2 focus:ring-blue-500 transition-all bg-white text-gray-900 placeholder-gray-500"
                    placeholder="••••••••"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    required
                  />
                </div>

                <div className="flex items-center">
                  <input
                    type="checkbox"
                    id="rememberMe"
                    className="w-4 h-4 text-blue-600 border-2 border-gray-300 rounded focus:ring-2 focus:ring-blue-500 cursor-pointer"
                    checked={rememberMe}
                    onChange={(e) => setRememberMe(e.target.checked)}
                  />
                  <label htmlFor="rememberMe" className="ml-2 text-sm font-medium text-gray-700 cursor-pointer">
                    Remember me
                  </label>
                </div>

                {error && (
                  <div className="bg-gradient-to-r from-red-50 to-red-100 border border-red-200 text-red-700 px-4 py-3 rounded-xl text-sm font-medium">
                    {error}
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
                    <div className="w-full border-t border-gray-300"></div>
                  </div>
                  <div className="relative flex justify-center text-sm">
                    <span className="px-4 bg-white text-gray-500 font-medium">Don't have an account?</span>
                  </div>
                </div>

                <button
                  type="button"
                  className="w-full bg-gradient-to-r from-blue-50 to-blue-100 text-blue-700 py-3 rounded-xl font-semibold border-2 border-blue-200 hover:border-blue-300 hover:shadow-md transition-all duration-200"
                  onClick={() => navigate('/create')}
                >
                  Create Account
                </button>
              </form>

              <p className="text-center text-xs text-gray-500 mt-6">
                By signing in, you agree to our{' '}
                <button className="text-blue-600 hover:text-blue-700 font-medium">Terms of Service</button>
                {' '}and{' '}
                <button className="text-blue-600 hover:text-blue-700 font-medium">Privacy Policy</button>
              </p>
            </div>
          </div>
          </div>
        </div>
      </div>
    </div>
  );
}