import React from 'react';

const Button = ({
    children,
    variant = 'primary',
    className = '',
    type = 'button',
    fullWidth = false,
    ...props
}) => {
    const baseStyles = "py-2.5 px-4 rounded-lg font-medium transition-all duration-200 focus:outline-none focus:ring-2 focus:ring-offset-2 dark:focus:ring-offset-slate-900";

    const variants = {
        // Premium gradient variants
        primary: "bg-gradient-to-r from-blue-600 to-blue-700 text-white hover:shadow-lg hover:-translate-y-0.5 focus:ring-blue-500 dark:focus:ring-blue-400",
        gradient: "bg-gradient-to-r from-blue-500 to-purple-600 text-white hover:shadow-xl hover:-translate-y-0.5 focus:ring-purple-500 dark:focus:ring-purple-400",
        'gradient-secondary': "bg-gradient-to-r from-purple-500 to-pink-600 text-white hover:shadow-xl hover:-translate-y-0.5 focus:ring-pink-500 dark:focus:ring-pink-400",

        // Enhanced existing variants
        secondary: "bg-gradient-to-r from-blue-50 to-blue-100 dark:from-blue-900/30 dark:to-blue-800/30 text-blue-700 dark:text-blue-300 border-2 border-blue-200 dark:border-blue-800 hover:border-blue-300 dark:hover:border-blue-700 hover:shadow-md hover:-translate-y-0.5 focus:ring-blue-500 dark:focus:ring-blue-400",
        outline: "bg-white dark:bg-slate-800 text-gray-700 dark:text-slate-200 border-2 border-gray-300 dark:border-slate-600 hover:border-gray-400 dark:hover:border-slate-500 hover:bg-gray-50 dark:hover:bg-slate-700 hover:shadow-md transition-all focus:ring-gray-500 dark:focus:ring-slate-400",
        danger: "bg-gradient-to-r from-red-600 to-red-700 text-white hover:shadow-lg hover:-translate-y-0.5 focus:ring-red-500 dark:focus:ring-red-400",

        // New premium variants
        success: "bg-gradient-to-r from-green-600 to-emerald-700 text-white hover:shadow-lg hover:-translate-y-0.5 focus:ring-green-500 dark:focus:ring-green-400",
        warning: "bg-gradient-to-r from-orange-500 to-amber-600 text-white hover:shadow-lg hover:-translate-y-0.5 focus:ring-orange-500 dark:focus:ring-orange-400",
        ghost: "bg-transparent text-blue-600 dark:text-blue-400 hover:bg-blue-50 dark:hover:bg-blue-900/20 transition-all focus:ring-blue-500 dark:focus:ring-blue-400",
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
