import React from 'react';

const Input = ({
    label,
    id,
    error,
    helper,
    className = '',
    ...props
}) => {
    return (
        <div className={`space-y-1 ${className}`}>
            {label && (
                <label htmlFor={id} className="block text-xs font-medium text-gray-700 dark:text-slate-300">
                    {label}
                </label>
            )}
            <input
                id={id}
                className={`w-full border rounded px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-blue-500 dark:focus:ring-blue-400 focus:border-blue-500 dark:focus:border-blue-400 transition bg-white dark:bg-slate-800 text-gray-900 dark:text-slate-100 placeholder-gray-400 dark:placeholder-slate-500 ${error ? 'border-red-500 dark:border-red-400' : 'border-gray-300 dark:border-slate-600'
                    }`}
                {...props}
            />
            {helper && !error && <p className="text-xs text-gray-500 dark:text-slate-400">{helper}</p>}
            {error && <p className="text-red-500 dark:text-red-400 text-xs">{error}</p>}
        </div>
    );
};

export default Input;
