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
    <div className="flex min-h-screen bg-gray-50 dark:bg-slate-900 font-sans">
      {/* Left Panel - Completely new design */}
      <div className="hidden lg:flex lg:w-1/2 bg-gradient-to-br from-blue-700 via-blue-600 to-indigo-700 text-white p-12 flex-col justify-between">
        <div>
          <h1 className="text-5xl font-bold tracking-tight mb-6">
            Your Health,<br />Your Control
          </h1>
          <p className="text-xl opacity-90 max-w-lg leading-relaxed">
            Join a secure, patient-centered platform that puts you at the center of your care — with full visibility, privacy controls, and direct access to your healthcare team.
          </p>
        </div>

        <div className="space-y-8">
          <div className="grid grid-cols-2 gap-6">
            <div className="bg-white/10 backdrop-blur-sm rounded-xl p-6 border border-white/20">
              <div className="text-3xl mb-2">🔒</div>
              <h3 className="font-semibold text-lg">Bank-grade Security</h3>
              <p className="text-sm opacity-80 mt-1">End-to-end encryption & HIPAA compliant</p>
            </div>
            <div className="bg-white/10 backdrop-blur-sm rounded-xl p-6 border border-white/20">
              <div className="text-3xl mb-2">📱</div>
              <h3 className="font-semibold text-lg">Always Connected</h3>
              <p className="text-sm opacity-80 mt-1">Access records & communicate 24/7</p>
            </div>
          </div>

          <div className="bg-white/10 backdrop-blur-sm rounded-xl p-6 border border-white/20">
            <p className="text-sm opacity-90 italic">
              "Your medical data belongs to you. We only facilitate secure, consented access."
            </p>
            <p className="text-xs mt-3 opacity-70">— Our Privacy Promise</p>
          </div>
        </div>

        <div className="text-sm opacity-70">
          © 2026 SecureCare Platform • All rights reserved
        </div>
      </div>

      {/* Right Panel - Form */}
      <div className="w-full lg:w-1/2 flex items-center justify-center p-6 sm:p-12 bg-white dark:bg-slate-800">
        <div className="w-full max-w-md">
          <div className="mb-10">
            <h2 className="text-3xl font-bold text-gray-900 dark:text-slate-100">Create Your Patient Account</h2>
            <p className="mt-3 text-gray-600 dark:text-slate-400">
              Get started with secure access to your health records and care team
            </p>
          </div>

          <form onSubmit={handleSignUp} className="space-y-6">
            <div>
              <label htmlFor="name" className="block text-sm font-medium text-gray-700 dark:text-slate-200 mb-1.5">
                Full Name
              </label>
              <input
                id="name"
                type="text"
                autoComplete="name"
                required
                className="block w-full rounded-lg border border-gray-300 dark:border-slate-600 px-4 py-3 text-gray-900 dark:text-slate-100 placeholder-gray-400 dark:placeholder-slate-500 bg-white dark:bg-slate-800 focus:border-blue-500 focus:ring-1 focus:ring-blue-500 transition"
                placeholder="Enter your full name"
                value={name}
                onChange={(e) => setName(e.target.value)}
              />
            </div>

            <div>
              <label htmlFor="email" className="block text-sm font-medium text-gray-700 dark:text-slate-200 mb-1.5">
                Email Address
              </label>
              <input
                id="email"
                type="email"
                autoComplete="email"
                required
                className="block w-full rounded-lg border border-gray-300 dark:border-slate-600 px-4 py-3 text-gray-900 dark:text-slate-100 placeholder-gray-400 dark:placeholder-slate-500 bg-white dark:bg-slate-800 focus:border-blue-500 focus:ring-1 focus:ring-blue-500 transition"
                placeholder="you@example.com"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
              />
            </div>

            <div>
              <label htmlFor="phone" className="block text-sm font-medium text-gray-700 dark:text-slate-200 mb-1.5">
                Mobile Number
              </label>
              <input
                id="phone"
                type="tel"
                autoComplete="tel"
                required
                className="block w-full rounded-lg border border-gray-300 dark:border-slate-600 px-4 py-3 text-gray-900 dark:text-slate-100 placeholder-gray-400 dark:placeholder-slate-500 bg-white dark:bg-slate-800 focus:border-blue-500 focus:ring-1 focus:ring-blue-500 transition"
                placeholder="10-digit mobile number"
                value={phone}
                onChange={(e) => setPhone(e.target.value)}
              />
            </div>

            <div>
              <label htmlFor="password" className="block text-sm font-medium text-gray-700 dark:text-slate-200 mb-1.5">
                Password
              </label>
              <input
                id="password"
                type="password"
                autoComplete="new-password"
                required
                className="block w-full rounded-lg border border-gray-300 dark:border-slate-600 px-4 py-3 text-gray-900 dark:text-slate-100 placeholder-gray-400 dark:placeholder-slate-500 bg-white dark:bg-slate-800 focus:border-blue-500 focus:ring-1 focus:ring-blue-500 transition"
                placeholder="At least 12 characters"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
              />
            </div>

            <div>
              <label htmlFor="confirmPassword" className="block text-sm font-medium text-gray-700 dark:text-slate-200 mb-1.5">
                Confirm Password
              </label>
              <input
                id="confirmPassword"
                type="password"
                autoComplete="new-password"
                required
                className="block w-full rounded-lg border border-gray-300 dark:border-slate-600 px-4 py-3 text-gray-900 dark:text-slate-100 placeholder-gray-400 dark:placeholder-slate-500 bg-white dark:bg-slate-800 focus:border-blue-500 focus:ring-1 focus:ring-blue-500 transition"
                placeholder="Re-enter password"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
              />
            </div>

            {error && (
              <div className="rounded-md bg-red-50 dark:bg-red-900/30 p-3 text-sm text-red-700 dark:text-red-300">
                {error}
              </div>
            )}

            {success && (
              <div className="rounded-md bg-green-50 dark:bg-green-900/30 p-3 text-sm text-green-700 dark:text-green-300">
                {success}
              </div>
            )}

            <button
              type="submit"
              disabled={loading}
              className="w-full bg-blue-600 text-white py-3.5 px-4 rounded-lg font-medium hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 transition duration-200 shadow-sm disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {loading ? 'Creating Account...' : 'Create Account'}
            </button>

            <div className="text-center text-sm text-gray-500 dark:text-slate-400 mt-6">
              Already have an account?{' '}
              <button
                type="button"
                className="font-medium text-blue-600 dark:text-blue-400 hover:text-blue-500 dark:hover:text-blue-300 transition"
                onClick={() => navigate('/')}
              >
                Sign in
              </button>
            </div>

            <p className="text-center text-xs text-gray-400 dark:text-slate-500 mt-8">
              By creating an account, you agree to our{' '}
              <button className="text-gray-500 dark:text-slate-400 underline hover:text-gray-700 dark:hover:text-slate-300 bg-transparent border-none cursor-pointer p-0 font-inherit">
                Terms of Service
              </button>{' '}
              and{' '}
              <button className="text-gray-500 dark:text-slate-400 underline hover:text-gray-700 dark:hover:text-slate-300 bg-transparent border-none cursor-pointer p-0 font-inherit">
                Privacy Policy
              </button>
            </p>
          </form>
        </div>
      </div>
    </div>
  );
}
