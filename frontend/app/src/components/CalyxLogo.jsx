import React from 'react';

/**
 * CALYX Logo Component
 * Premium Healthcare AI Platform Logo
 * Features: Blue gradient head with circuit/neural network pattern
 */
export default function CalyxLogo({ size = 'medium', showText = true, className = '' }) {
  const sizeClasses = {
    small: 'w-8 h-8',
    medium: 'w-10 h-10',
    large: 'w-12 h-12',
    xl: 'w-16 h-16'
  };

  const textSizeClasses = {
    small: 'text-xs',
    medium: 'text-sm',
    large: 'text-base',
    xl: 'text-lg'
  };

  return (
    <div className={`flex items-center gap-2 ${className}`}>
      {/* Logo SVG */}
      <svg
        viewBox="0 0 200 240"
        className={`${sizeClasses[size]} flex-shrink-0`}
        fill="none"
        xmlns="http://www.w3.org/2000/svg"
      >
        {/* Head Shape - Gradient Fill */}
        <defs>
          <linearGradient id="headGradient" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stopColor="#3B82F6" />
            <stop offset="100%" stopColor="#1565C0" />
          </linearGradient>
          <linearGradient id="accentGradient" x1="0%" y1="0%" x2="100%" y2="0%">
            <stop offset="0%" stopColor="#60A5FA" />
            <stop offset="100%" stopColor="#3B82F6" />
          </linearGradient>
        </defs>

        {/* Main Head Silhouette */}
        <path
          d="M60 50C60 50 40 70 40 100C40 130 50 160 80 180L120 180C150 160 160 130 160 100C160 70 140 50 120 50C110 45 90 40 90 40C90 40 75 40 60 50Z"
          fill="url(#headGradient)"
        />

        {/* Brain/Circuit Pattern on Side - Dots */}
        <circle cx="35" cy="55" r="3.5" fill="url(#accentGradient)" opacity="0.9" />
        <circle cx="32" cy="70" r="3" fill="url(#accentGradient)" opacity="0.8" />
        <circle cx="35" cy="85" r="3.5" fill="url(#accentGradient)" opacity="0.9" />
        <circle cx="42" cy="100" r="3" fill="url(#accentGradient)" opacity="0.8" />
        <circle cx="30" cy="105" r="2.5" fill="url(#accentGradient)" opacity="0.7" />
        <circle cx="38" cy="120" r="3" fill="url(#accentGradient)" opacity="0.8" />

        {/* Neural Network Connections */}
        <line
          x1="35"
          y1="55"
          x2="32"
          y2="70"
          stroke="url(#accentGradient)"
          strokeWidth="1.5"
          opacity="0.6"
        />
        <line
          x1="32"
          y1="70"
          x2="35"
          y2="85"
          stroke="url(#accentGradient)"
          strokeWidth="1.5"
          opacity="0.6"
        />
        <line
          x1="35"
          y1="85"
          x2="42"
          y2="100"
          stroke="url(#accentGradient)"
          strokeWidth="1.5"
          opacity="0.6"
        />
        <line
          x1="42"
          y1="100"
          x2="30"
          y2="105"
          stroke="url(#accentGradient)"
          strokeWidth="1.5"
          opacity="0.6"
        />
        <line
          x1="30"
          y1="105"
          x2="38"
          y2="120"
          stroke="url(#accentGradient)"
          strokeWidth="1.5"
          opacity="0.6"
        />

        {/* Additional neural nodes for complexity */}
        <circle cx="28" cy="90" r="2" fill="url(#accentGradient)" opacity="0.6" />
        <circle cx="40" cy="110" r="2" fill="url(#accentGradient)" opacity="0.6" />

        {/* Connecting lines to neural nodes */}
        <line
          x1="35"
          y1="85"
          x2="28"
          y2="90"
          stroke="url(#accentGradient)"
          strokeWidth="1"
          opacity="0.5"
        />
        <line
          x1="42"
          y1="100"
          x2="40"
          y2="110"
          stroke="url(#accentGradient)"
          strokeWidth="1"
          opacity="0.5"
        />

        {/* Eye */}
        <circle cx="75" cy="75" r="4" fill="white" opacity="0.9" />
        <circle cx="75" cy="75" r="2.5" fill="#000000" opacity="0.8" />

        {/* Subtle highlight on head */}
        <ellipse cx="95" cy="60" rx="15" ry="10" fill="white" opacity="0.15" />
      </svg>

      {/* Text - Only show if showText is true and size is not small */}
      {showText && size !== 'small' && (
        <span className={`font-bold bg-clip-text text-transparent bg-gradient-to-r from-blue-600 to-blue-800 dark:from-blue-400 dark:to-blue-300 ${textSizeClasses[size]} whitespace-nowrap`}>
          CALYX
        </span>
      )}
    </div>
  );
}
