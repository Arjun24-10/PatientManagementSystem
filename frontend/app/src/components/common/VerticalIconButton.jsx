import React from 'react';

/**
 * VerticalIconButton - Vertical layout (Icon Above Text)
 * Use this for compact spaces or icon-heavy interfaces.
 */
const VerticalIconButton = ({ 
  icon: Icon, 
  label, 
  variant = 'secondary', 
  size = 'default',
  onClick, 
  disabled = false, 
  className = '',
  ...props 
}) => {
  const baseClasses = "flex flex-col items-center rounded-md font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed";
  
  const sizeClasses = {
    sm: "gap-1 px-3 py-2 text-xs min-w-[60px]",
    default: "gap-1.5 px-4 py-3 text-xs min-w-[80px]",
    lg: "gap-2 px-5 py-4 text-sm min-w-[100px]"
  };
  
  const variants = {
    primary: "bg-blue-600 dark:bg-blue-500 text-white hover:bg-blue-700 dark:hover:bg-blue-600 disabled:hover:bg-blue-600",
    secondary: "bg-white dark:bg-slate-800 border border-gray-300 dark:border-slate-600 text-gray-700 dark:text-slate-300 hover:bg-gray-50 dark:hover:bg-slate-700",
    danger: "bg-red-600 text-white hover:bg-red-700 disabled:hover:bg-red-600",
    ghost: "text-gray-700 dark:text-slate-300 hover:bg-gray-100 dark:hover:bg-slate-800",
    outline: "bg-white dark:bg-slate-800 border border-gray-300 dark:border-slate-600 text-gray-700 dark:text-slate-300 hover:bg-gray-50 dark:hover:bg-slate-700"
  };

  const iconSizeClass = size === 'sm' ? 'w-4 h-4' : size === 'lg' ? 'w-6 h-6' : 'w-5 h-5';
  
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

export default VerticalIconButton;