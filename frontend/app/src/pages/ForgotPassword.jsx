import React, { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { ArrowLeft, Mail, AlertCircle, CheckCircle, X, Send, Shield } from 'lucide-react';
import { forgotPassword } from '../services/supabaseAuth';

export default function ForgotPassword() {
  const navigate = useNavigate();

  const [email, setEmail] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [emailSent, setEmailSent] = useState(false);
  const [fieldError, setFieldError] = useState('');

  // Email validation
  const validateEmail = (value) => {
    if (!value) {
      return 'Email is required';
    }
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(value)) {
      return 'Please enter a valid email address';
    }
    return '';
  };

  const handleEmailBlur = () => {
    setFieldError(validateEmail(email));
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setSuccess('');

    // Validate email
    const emailError = validateEmail(email);
    if (emailError) {
      setFieldError(emailError);
      return;
    }

    setLoading(true);

    try {
      const result = await forgotPassword(email);

      if (result.success) {
        setSuccess('If an account exists with this email, a password reset link has been sent.');
        setEmailSent(true);
      } else {
        // For security, we show the same message even on error
        setSuccess('If an account exists with this email, a password reset link has been sent.');
        setEmailSent(true);
      }
    } catch (err) {
      // For security, we don't reveal if email exists or not
      setSuccess('If an account exists with this email, a password reset link has been sent.');
      setEmailSent(true);
    } finally {
      setLoading(false);
    }
  };

  const handleResendEmail = async () => {
    setLoading(true);
    setSuccess('');

    try {
      await forgotPassword(email);
      setSuccess('A new reset link has been sent to your email.');
    } catch (err) {
      setSuccess('A new reset link has been sent to your email.');
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

            {/* Left Panel - Branding */}
            <div className="hidden lg:block space-y-6 animate-fade-in">
              {/* CALYX Logo Section */}
              <div className="flex items-center gap-3 px-4 py-4 bg-gradient-to-br from-blue-100 to-purple-100 dark:from-blue-900/20 dark:to-purple-900/20 rounded-2xl border border-blue-200/50 dark:border-blue-800/30">
                <img src="/calyx-logo.png" alt="CALYX" className="h-16 w-16 object-contain" />
                <div>
                  <h1 className="text-2xl font-bold text-blue-600 dark:text-blue-400">CALYX</h1>
                  <p className="text-xs text-gray-600 dark:text-slate-400">Healthcare Management</p>
                </div>
              </div>

              <div className="space-y-2">
                <div className="inline-flex items-center gap-1.5 px-2.5 py-1 bg-white/50 dark:bg-slate-800/50 backdrop-blur-sm rounded-full border border-white/20 dark:border-slate-700/50">
                  <Shield className="w-4 h-4 text-blue-600 dark:text-blue-400" />
                  <span className="text-xs font-semibold text-gray-700 dark:text-slate-200">Secure Account Recovery</span>
                </div>

                <h2 className="text-3xl font-bold leading-tight">
                  <span className="bg-gradient-to-r from-blue-600 to-purple-600 bg-clip-text text-transparent">
                    Forgot Password?
                  </span>
                  <br />
                  <span className="text-gray-800 dark:text-slate-100">We've got you covered.</span>
                </h2>

                <p className="text-sm text-gray-600 dark:text-slate-400 max-w-md">
                  Enter your email address to receive a secure link to reset your password. The link will expire in 30 minutes for your security.
                </p>
              </div>
            </div>

            {/* Right Panel - Form */}
            <div className="glass-card dark:bg-slate-800/80 dark:border-slate-700/50 p-6 md:p-8 rounded-2xl animate-fade-in-delay-1 relative z-20">
              <div className="space-y-4 relative z-20">
                {/* Back Link */}
                <button
                  onClick={() => navigate('/login')}
                  className="flex items-center text-xs text-gray-500 dark:text-slate-400 hover:text-blue-600 dark:hover:text-blue-400 transition-colors mb-2"
                >
                  <ArrowLeft className="h-3 w-3 mr-1" />
                  Back to Login
                </button>

                <div className="space-y-1">
                  <h2 className="text-xl font-bold text-gray-900 dark:text-slate-100">
                    {emailSent ? 'Check Your Email' : 'Reset Password'}
                  </h2>
                  <p className="text-xs text-gray-600 dark:text-slate-400">
                    {emailSent ? 'We have sent you a recovery link' : 'Enter your email to verify your identity'}
                  </p>
                </div>

                {/* Error Alert */}
                {error && (
                  <div className="bg-gradient-to-r from-red-50 to-red-100 dark:from-red-900/30 dark:to-red-800/30 border border-red-200 dark:border-red-800 text-red-700 dark:text-red-300 px-3 py-2 rounded-lg text-xs font-medium flex items-center justify-between animate-shake">
                    <div className="flex items-center gap-1.5">
                      <AlertCircle className="h-4 w-4 text-red-500" />
                      <span>{error}</span>
                    </div>
                    <button
                      type="button"
                      onClick={() => setError('')}
                      className="text-red-500 dark:text-red-400 hover:text-red-700 dark:hover:text-red-300 transition-colors"
                    >
                      <X className="h-3.5 w-3.5" />
                    </button>
                  </div>
                )}

                {/* Success Alert */}
                {success && (
                  <div className="bg-gradient-to-r from-green-50 to-green-100 dark:from-green-900/30 dark:to-green-800/30 border border-green-200 dark:border-green-800 text-green-700 dark:text-green-300 px-3 py-2 rounded-lg text-xs font-medium flex items-center gap-1.5">
                    <CheckCircle className="h-4 w-4 text-green-500" />
                    <span>{success}</span>
                  </div>
                )}

                {!emailSent ? (
                  <form onSubmit={handleSubmit} className="space-y-3 relative z-20">
                    <div className="space-y-1">
                      <label htmlFor="email" className="block text-xs font-semibold text-gray-700 dark:text-slate-200">
                        Email Address
                      </label>
                      <div className="relative">
                        <div className="absolute inset-y-0 left-0 pl-2.5 flex items-center pointer-events-none">
                          <Mail className="h-4 w-4 text-gray-400 dark:text-slate-500" />
                        </div>
                        <input
                          type="email"
                          id="email"
                          className={`w-full border-2 rounded-lg pl-8 pr-3 py-2 text-sm focus:outline-none focus:ring-2 transition-all bg-white dark:bg-slate-800 text-gray-900 dark:text-slate-100 placeholder-gray-500 dark:placeholder-slate-500 ${fieldError
                            ? 'border-red-300 dark:border-red-500 focus:ring-red-500 focus:border-red-500'
                            : 'border-gray-300 dark:border-slate-600 focus:ring-blue-500 focus:border-blue-500'
                            }`}
                          placeholder="Enter your email"
                          value={email}
                          onChange={(e) => setEmail(e.target.value)}
                          onBlur={handleEmailBlur}
                          disabled={loading}
                        />
                      </div>
                      {fieldError && (
                        <p className="text-xs text-red-600 dark:text-red-400 flex items-center gap-1">
                          <AlertCircle className="h-3 w-3" />
                          {fieldError}
                        </p>
                      )}
                    </div>

                    <button
                      type="submit"
                      disabled={loading || !email}
                      className="w-full bg-gradient-to-r from-blue-600 to-purple-600 text-white py-2.5 rounded-lg text-sm font-semibold hover:shadow-xl hover:-translate-y-0.5 transition-all duration-200 disabled:opacity-50 disabled:cursor-not-allowed disabled:transform-none flex items-center justify-center gap-2"
                    >
                      {loading ? (
                        <>
                          <svg className="animate-spin h-4 w-4 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                            <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                            <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                          </svg>
                          <span>Sending...</span>
                        </>
                      ) : (
                        <>
                          <Send className="h-4 w-4" />
                          <span>Send Reset Link</span>
                        </>
                      )}
                    </button>
                  </form>
                ) : (
                  <div className="space-y-4 relative z-20">
                    <div className="p-3 bg-blue-50 dark:bg-blue-900/20 rounded-lg text-center border border-blue-100 dark:border-blue-800">
                      <p className="text-xs text-gray-500 dark:text-slate-400 mb-1">Sent to</p>
                      <p className="font-semibold text-gray-900 dark:text-slate-100 text-sm">{email}</p>
                    </div>

                    <div className="text-center space-y-2">
                      <p className="text-xs text-gray-600 dark:text-slate-400">
                        Didn't receive the email?
                      </p>
                      <button
                        onClick={handleResendEmail}
                        disabled={loading}
                        className="text-xs font-semibold text-blue-600 dark:text-blue-400 hover:text-blue-700 dark:hover:text-blue-300 transition-colors disabled:opacity-50"
                      >
                        {loading ? 'Sending...' : 'Click to resend'}
                      </button>
                    </div>

                    <button
                      onClick={() => navigate('/login')}
                      className="w-full bg-gray-100 dark:bg-slate-700 text-gray-700 dark:text-slate-200 py-2.5 rounded-lg text-sm font-semibold hover:bg-gray-200 dark:hover:bg-slate-600 transition-colors"
                    >
                      Return to Login
                    </button>
                  </div>
                )}

                {/* Help Text */}
                <div className="mt-6 text-center text-xs text-gray-500 dark:text-slate-400">
                  Remember your password?{' '}
                  <Link to="/login" className="text-blue-600 dark:text-blue-400 hover:text-blue-700 dark:hover:text-blue-300 font-medium transition-colors">
                    Sign in
                  </Link>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
