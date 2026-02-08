import React from 'react';

const Button = ({
    children,
    variant = 'primary',
    className = '',
    type = 'button',
    fullWidth = false,
    ...props
}) => {
    const baseStyles = "py-3 px-4 rounded-xl font-semibold transition-all duration-200 focus:outline-none focus:ring-2 focus:ring-offset-2";

    const variants = {
        // Premium gradient variants
        primary: "bg-gradient-to-r from-blue-600 to-blue-700 text-white hover:shadow-lg hover:-translate-y-0.5 focus:ring-blue-500",
        gradient: "bg-gradient-to-r from-blue-500 to-purple-600 text-white hover:shadow-xl hover:-translate-y-0.5 focus:ring-purple-500",
        'gradient-secondary': "bg-gradient-to-r from-purple-500 to-pink-600 text-white hover:shadow-xl hover:-translate-y-0.5 focus:ring-pink-500",

        // Enhanced existing variants
        secondary: "bg-gradient-to-r from-blue-50 to-blue-100 text-blue-700 border-2 border-blue-200 hover:border-blue-300 hover:shadow-md hover:-translate-y-0.5 focus:ring-blue-500",
        outline: "bg-white text-gray-700 border-2 border-gray-300 hover:border-gray-400 hover:bg-gray-50 hover:shadow-md transition-all focus:ring-gray-500",
        danger: "bg-gradient-to-r from-red-600 to-red-700 text-white hover:shadow-lg hover:-translate-y-0.5 focus:ring-red-500",

        // New premium variants
        success: "bg-gradient-to-r from-green-600 to-emerald-700 text-white hover:shadow-lg hover:-translate-y-0.5 focus:ring-green-500",
        warning: "bg-gradient-to-r from-orange-500 to-amber-600 text-white hover:shadow-lg hover:-translate-y-0.5 focus:ring-orange-500",
        ghost: "bg-transparent text-blue-600 hover:bg-blue-50 transition-all focus:ring-blue-500",
        link: "bg-transparent text-blue-600 hover:text-blue-700 underline-offset-4 hover:underline p-0 focus:ring-0",
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
