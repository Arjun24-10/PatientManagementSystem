import React from 'react';

const Input = ({
    label,
    id,
    error,
    className = '',
    ...props
}) => {
    return (
        <div className={className}>
            {label && (
                <label htmlFor={id} className="block mb-2 text-sm font-semibold text-gray-700 dark:text-slate-300">
                    {label}
                </label>
            )}
            <input
                id={id}
                className={`w-full border-2 rounded-lg px-4 py-3 focus:outline-none focus:border-blue-500 dark:focus:border-blue-400 transition bg-white dark:bg-slate-800 text-gray-900 dark:text-slate-100 placeholder-gray-400 dark:placeholder-slate-500 ${error ? 'border-red-500 dark:border-red-400 focus:border-red-500 dark:focus:border-red-400' : 'border-gray-200 dark:border-slate-700'
                    }`}
                {...props}
            />
            {error && <p className="text-red-500 dark:text-red-400 text-sm font-medium mt-1">{error}</p>}
        </div>
    );
};

export default Input;
