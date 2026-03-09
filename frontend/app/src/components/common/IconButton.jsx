import React from 'react';

/**
 * IconButton - Horizontal layout (Icon + Text Side-by-Side)
 * Use this for primary actions and when space permits.
 */
const IconButton = ({ 
  icon: Icon, 
  label, 
  variant = 'secondary', 
  size = 'default',
  onClick, 
  disabled = false, 
  className = '',
  ...props 
}) => {
  const baseClasses = "inline-flex items-center rounded-md font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed";
  
  const sizeClasses = {
    sm: "gap-1.5 px-3 py-1.5 text-xs",
    default: "gap-2 px-4 py-2 text-sm",
    lg: "gap-2 px-5 py-2.5 text-sm"
  };
  
  const variants = {
    primary: "bg-blue-600 dark:bg-blue-500 text-white hover:bg-blue-700 dark:hover:bg-blue-600 disabled:hover:bg-blue-600",
    secondary: "bg-white dark:bg-slate-800 border border-gray-300 dark:border-slate-600 text-gray-700 dark:text-slate-300 hover:bg-gray-50 dark:hover:bg-slate-700",
    danger: "bg-red-600 text-white hover:bg-red-700 disabled:hover:bg-red-600",
    ghost: "text-gray-700 dark:text-slate-300 hover:bg-gray-100 dark:hover:bg-slate-800",
    outline: "bg-white dark:bg-slate-800 border border-gray-300 dark:border-slate-600 text-gray-700 dark:text-slate-300 hover:bg-gray-50 dark:hover:bg-slate-700"
  };

  const iconSizeClass = size === 'sm' ? 'w-3.5 h-3.5' : 'w-4 h-4';
  
  return (
    <button 
      className={`${baseClasses} ${sizeClasses[size]} ${variants[variant]} ${className}`}
      onClick={onClick}
      disabled={disabled}
      {...props}
    >
      {Icon && <Icon className={iconSizeClass} />}
      {label && <span>{label}</span>}
    </button>
  );
};

export default IconButton;