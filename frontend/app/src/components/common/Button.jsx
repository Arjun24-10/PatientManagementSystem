import React from 'react';

const Button = ({
    children,
    variant = 'primary',
    size = 'default',
    className = '',
    type = 'button',
    fullWidth = false,
    ...props
}) => {
    const sizeStyles = {
        sm: 'py-1 px-2.5 text-xs',
        default: 'py-1.5 px-3 text-sm',
        lg: 'py-2 px-4 text-sm',
    };

    const baseStyles = `${sizeStyles[size] || sizeStyles.default} rounded-md font-medium transition-all duration-150 focus:outline-none focus:ring-1 focus:ring-offset-1 dark:focus:ring-offset-slate-900`;

    const variants = {
        primary: "bg-blue-600 dark:bg-blue-500 text-white hover:bg-blue-700 dark:hover:bg-blue-600 focus:ring-blue-500 dark:focus:ring-blue-400",
        gradient: "bg-blue-600 dark:bg-blue-500 text-white hover:bg-blue-700 dark:hover:bg-blue-600 focus:ring-blue-500 dark:focus:ring-blue-400",
        'gradient-secondary': "bg-purple-600 dark:bg-purple-500 text-white hover:bg-purple-700 dark:hover:bg-purple-600 focus:ring-purple-500 dark:focus:ring-purple-400",
        secondary: "bg-blue-50 dark:bg-blue-900/30 text-blue-700 dark:text-blue-300 border border-blue-200 dark:border-blue-800 hover:bg-blue-100 dark:hover:bg-blue-900/50 focus:ring-blue-500 dark:focus:ring-blue-400",
        outline: "bg-white dark:bg-slate-800 text-gray-700 dark:text-slate-200 border border-gray-300 dark:border-slate-600 hover:bg-gray-50 dark:hover:bg-slate-700 focus:ring-gray-500 dark:focus:ring-slate-400",
        danger: "bg-red-600 dark:bg-red-500 text-white hover:bg-red-700 dark:hover:bg-red-600 focus:ring-red-500 dark:focus:ring-red-400",
        success: "bg-green-600 dark:bg-green-500 text-white hover:bg-green-700 dark:hover:bg-green-600 focus:ring-green-500 dark:focus:ring-green-400",
        warning: "bg-orange-500 dark:bg-orange-400 text-white hover:bg-orange-600 dark:hover:bg-orange-500 focus:ring-orange-500 dark:focus:ring-orange-400",
        ghost: "bg-transparent text-blue-600 dark:text-blue-400 hover:bg-blue-50 dark:hover:bg-blue-900/20 focus:ring-blue-500 dark:focus:ring-blue-400",
        link: "bg-transparent text-blue-600 dark:text-blue-400 hover:text-blue-700 dark:hover:text-blue-300 underline-offset-4 hover:underline p-0 focus:ring-0",
    };

    const widthClass = fullWidth ? "w-full" : "";

    return (
        <button
            type={type}
            className={`${baseStyles} ${variants[variant]} ${widthClass} ${className}`}
            {...props}
        >
            {children}
        </button>
    );
};

export default Button;
