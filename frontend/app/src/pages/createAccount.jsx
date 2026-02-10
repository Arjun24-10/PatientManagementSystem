import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';

export default function CreateAccount() {
  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [phone, setPhone] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [loading, setLoading] = useState(false);

  const navigate = useNavigate();
  const { signup } = useAuth();

  const handleSignUp = async (e) => {
    e.preventDefault();
    setError('');
    setSuccess('');

    // Basic validation
    if (!name.trim() || !email || !phone || !password || !confirmPassword) {
      setError('Please complete all required fields');
      return;
    }

    if (password !== confirmPassword) {
      setError('Passwords do not match');
      return;
    }

    if (password.length < 12) {
      setError('Password must be at least 12 characters long');
      return;
    }

    // Very basic phone check (10 digits after removing non-digits)
    const phoneDigits = phone.replace(/\D/g, '');
    if (phoneDigits.length !== 10) {
      setError('Please enter a valid 10-digit phone number');
      return;
    }

    // Call backend API to register user
    setLoading(true);
    try {
      const result = await signup(email, password, { role: 'PATIENT', name, phone });
      
      if (result.success) {
        setSuccess('Account created successfully! Redirecting to sign in...');
        setTimeout(() => {
          navigate('/');
        }, 2200);
      } else {
        setError(result.error || 'Registration failed. Please try again.');
      }
    } catch (err) {
      setError(err.message || 'An error occurred during registration.');
    } finally {
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

            {/* Left Panel - Branding (copied from Login) */}
            <div className="hidden lg:block space-y-4 animate-fade-in">
              <div className="space-y-2">
                <div className="inline-flex items-center gap-1.5 px-2.5 py-1 bg-white/50 dark:bg-slate-800/50 backdrop-blur-sm rounded-full border border-white/20 dark:border-slate-700/50">
                  {/* Heart icon and branding text */}
                  {/* Import Heart from lucide-react if not already */}
                  <span className="text-xs font-semibold text-gray-700 dark:text-slate-200">Premium Healthcare Platform</span>
                </div>

                <h1 className="text-3xl font-bold leading-tight">
                  <span className="bg-gradient-to-r from-blue-600 to-purple-600 bg-clip-text text-transparent">
                    Expert Care,
                  </span>
                  <br />
                  <span className="text-gray-800 dark:text-slate-100">Always Available</span>
                </h1>

                  <div className="mt-2 space-y-1">
                    <p className="text-sm font-semibold text-blue-700 dark:text-blue-300">Your Health, Your Data, Your Control.</p>
                    <p className="text-sm text-gray-600 dark:text-slate-400">Secure Access to Personalized Care.</p>
                  </div>
                  <p className="text-sm text-gray-600 dark:text-slate-400 max-w-md">
                    {/* Minimal description or slogan can go here */}
                  </p>
              </div>
              {/* Stats Cards intentionally omitted for minimal UI */}
            </div>

            {/* Right Panel - Create Account Form (replaces Login form) */}
            <div className="glass-card dark:bg-slate-800/80 dark:border-slate-700/50 p-6 md:p-8 rounded-2xl animate-fade-in-delay-1 relative z-20">
              <div className="space-y-4 relative z-20">
                <div className="space-y-1">
                  <h2 className="text-xl font-bold text-gray-900 dark:text-slate-100">Create Account</h2>
                  <p className="text-xs text-gray-600 dark:text-slate-400">Sign up to access your healthcare dashboard</p>
                </div>
                <form onSubmit={handleSignUp} className="space-y-3 relative z-20">
                  <div className="space-y-1">
                    <label htmlFor="name" className="block text-xs font-semibold text-gray-700 dark:text-slate-200">Full Name</label>
                    <input
                      id="name"
                      type="text"
                      autoComplete="name"
                      required
                      className="w-full border-2 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 transition-all bg-white dark:bg-slate-800 text-gray-900 dark:text-slate-100 placeholder-gray-500 dark:placeholder-slate-500 border-gray-300 dark:border-slate-600 focus:ring-blue-500 focus:border-blue-500"
                      placeholder="Enter your full name"
                      value={name}
                      onChange={(e) => setName(e.target.value)}
                    />
                  </div>
                  <div className="space-y-1">
                    <label htmlFor="email" className="block text-xs font-semibold text-gray-700 dark:text-slate-200">Email Address</label>
                    <input
                      id="email"
                      type="email"
                      autoComplete="email"
                      required
                      className="w-full border-2 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 transition-all bg-white dark:bg-slate-800 text-gray-900 dark:text-slate-100 placeholder-gray-500 dark:placeholder-slate-500 border-gray-300 dark:border-slate-600 focus:ring-blue-500 focus:border-blue-500"
                      placeholder="you@example.com"
                      value={email}
                      onChange={(e) => setEmail(e.target.value)}
                    />
                  </div>
                  <div className="space-y-1">
                    <label htmlFor="phone" className="block text-xs font-semibold text-gray-700 dark:text-slate-200">Mobile Number</label>
                    <input
                      id="phone"
                      type="tel"
                      autoComplete="tel"
                      required
                      className="w-full border-2 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 transition-all bg-white dark:bg-slate-800 text-gray-900 dark:text-slate-100 placeholder-gray-500 dark:placeholder-slate-500 border-gray-300 dark:border-slate-600 focus:ring-blue-500 focus:border-blue-500"
                      placeholder="10-digit mobile number"
                      value={phone}
                      onChange={(e) => setPhone(e.target.value)}
                    />
                  </div>
                  <div className="space-y-1">
                    <label htmlFor="password" className="block text-xs font-semibold text-gray-700 dark:text-slate-200">Password</label>
                    <input
                      id="password"
                      type="password"
                      autoComplete="new-password"
                      required
                      className="w-full border-2 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 transition-all bg-white dark:bg-slate-800 text-gray-900 dark:text-slate-100 placeholder-gray-500 dark:placeholder-slate-500 border-gray-300 dark:border-slate-600 focus:ring-blue-500 focus:border-blue-500"
                      placeholder="At least 12 characters"
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                    />
                  </div>
                  <div className="space-y-1">
                    <label htmlFor="confirmPassword" className="block text-xs font-semibold text-gray-700 dark:text-slate-200">Confirm Password</label>
                    <input
                      id="confirmPassword"
                      type="password"
                      autoComplete="new-password"
                      required
                      className="w-full border-2 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 transition-all bg-white dark:bg-slate-800 text-gray-900 dark:text-slate-100 placeholder-gray-500 dark:placeholder-slate-500 border-gray-300 dark:border-slate-600 focus:ring-blue-500 focus:border-blue-500"
                      placeholder="Re-enter password"
                      value={confirmPassword}
                      onChange={(e) => setConfirmPassword(e.target.value)}
                    />
                  </div>
                  {error && (
                    <div className="bg-gradient-to-r from-red-50 to-red-100 dark:from-red-900/30 dark:to-red-800/30 border border-red-200 dark:border-red-800 text-red-700 dark:text-red-300 px-3 py-2 rounded-lg text-xs font-medium flex items-center justify-between animate-shake">
                      <span>{error}</span>
                    </div>
                  )}
                  {success && (
                    <div className="bg-gradient-to-r from-green-50 to-green-100 dark:from-green-900/30 dark:to-green-800/30 border border-green-200 dark:border-green-800 text-green-700 dark:text-green-300 px-3 py-2 rounded-lg text-xs font-medium flex items-center gap-1.5">
                      <span>{success}</span>
                    </div>
                  )}
                  <button
                    type="submit"
                    disabled={loading}
                    className="w-full bg-gradient-to-r from-blue-600 to-purple-600 text-white py-2.5 rounded-lg text-sm font-semibold hover:shadow-xl hover:-translate-y-0.5 transition-all duration-200 disabled:opacity-50 disabled:cursor-not-allowed disabled:transform-none"
                  >
                    {loading ? 'Creating Account...' : 'Create Account'}
                  </button>

                  <div className="relative my-4">
                    <div className="absolute inset-0 flex items-center">
                      <div className="w-full border-t border-gray-300 dark:border-slate-600"></div>
                    </div>
                    <div className="relative flex justify-center text-xs">
                      <span className="px-3 bg-white dark:bg-slate-800 text-gray-500 dark:text-slate-400 font-medium">Already have an account?</span>
                    </div>
                  </div>

                  <button
                    type="button"
                    className="w-full bg-gradient-to-r from-blue-50 to-blue-100 dark:from-blue-900/30 dark:to-blue-800/30 text-blue-700 dark:text-blue-300 py-2.5 rounded-lg text-sm font-semibold border-2 border-blue-200 dark:border-blue-700 hover:border-blue-300 dark:hover:border-blue-600 hover:shadow-md transition-all duration-200"
                    onClick={() => navigate('/')}
                  >
                    Sign In
                  </button>
                </form>

                <p className="text-center text-[10px] text-gray-500 dark:text-slate-400 mt-4">
                  By creating an account, you agree to our{' '}
                  <button className="text-blue-600 dark:text-blue-400 hover:text-blue-700 dark:hover:text-blue-300 font-medium">Terms of Service</button>
                  {' '}and{' '}
                  <button className="text-blue-600 dark:text-blue-400 hover:text-blue-700 dark:hover:text-blue-300 font-medium">Privacy Policy</button>
                </p>

                {/* Footer Links */}
                <div className="pt-3 border-t border-gray-200 dark:border-slate-700 mt-4">
                  <div className="flex items-center justify-center gap-3 text-[10px] text-gray-500 dark:text-slate-400">
                    <button className="hover:text-blue-600 dark:hover:text-blue-400 transition-colors">Privacy Policy</button>
                    <span>•</span>
                    <button className="hover:text-blue-600 dark:hover:text-blue-400 transition-colors">Terms of Service</button>
                    <span>•</span>
                    <button className="hover:text-blue-600 dark:hover:text-blue-400 transition-colors">Help</button>
                  </div>
                  <p className="text-center text-[10px] text-gray-400 dark:text-slate-500 mt-2">
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
