import React from 'react';

/**
 * IconOnlyButton - Icon-only layout (No Text, Tooltip Instead)
 * Use this for very compact spaces or when context is clear.
 */
const IconOnlyButton = ({ 
  icon: Icon, 
  tooltip, 
  variant = 'secondary', 
  size = 'default',
  onClick, 
  disabled = false, 
  className = '',
  ...props 
}) => {
  const baseClasses = "inline-flex items-center justify-center rounded-md transition-colors disabled:opacity-50 disabled:cursor-not-allowed";
  
  const sizeClasses = {
    sm: "w-7 h-7",
    default: "w-9 h-9",
    lg: "w-11 h-11"
  };
  
  const variants = {
    primary: "bg-blue-600 dark:bg-blue-500 text-white hover:bg-blue-700 dark:hover:bg-blue-600 disabled:hover:bg-blue-600",
    secondary: "bg-white dark:bg-slate-800 border border-gray-300 dark:border-slate-600 text-gray-600 dark:text-slate-400 hover:bg-gray-50 dark:hover:bg-slate-700",
    danger: "bg-red-600 text-white hover:bg-red-700 disabled:hover:bg-red-600",
    ghost: "text-gray-600 dark:text-slate-400 hover:bg-gray-100 dark:hover:bg-slate-800",
    "ghost-danger": "text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-900/20"
  };

  const iconSizeClass = size === 'sm' ? 'w-3.5 h-3.5' : size === 'lg' ? 'w-5 h-5' : 'w-4 h-4';
  
  return (
    <button 
      className={`${baseClasses} ${sizeClasses[size]} ${variants[variant]} ${className}`}
      onClick={onClick}
      disabled={disabled}
      title={tooltip}
      {...props}
    >
      {Icon && <Icon className={iconSizeClass} />}
    </button>
  );
};

export default IconOnlyButton;