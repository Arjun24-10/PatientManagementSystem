import React from 'react';
import { ChevronDown, AlertCircle } from 'lucide-react';

const Select = ({
    label,
    id,
    options = [],
    error,
    helper,
    className = '',
    value,
    onChange,
    placeholder = "Select an option",
    disabled = false,
    ...props
}) => {
    return (
        <div className={`space-y-1.5 ${className}`}>
            {label && (
                <label htmlFor={id} className="block text-sm font-medium text-gray-700 dark:text-gray-300">
                    {label}
                </label>
            )}
            <div className="relative">
                <select
                    id={id}
                    value={value}
                    onChange={onChange}
                    disabled={disabled}
                    className={`
                        block w-full rounded-lg border shadow-sm appearance-none transition-colors duration-200
                        pl-3 pr-10 py-2 text-sm
                        ${error
                            ? 'border-red-300 text-red-900 focus:border-red-500 focus:ring-red-500'
                            : 'border-gray-200 focus:border-primary focus:ring-primary'
                        }
                        disabled:bg-gray-50 disabled:text-gray-500
                        bg-white
                    `}
                    {...props}
                >
                    <option value="" disabled>{placeholder}</option>
                    {options.map((option) => (
                        <option key={option.value} value={option.value}>
                            {option.label}
                        </option>
                    ))}
                </select>

                <div className="absolute inset-y-0 right-0 pr-3 flex items-center pointer-events-none">
                    {error ? (
                        <AlertCircle className="h-4 w-4 text-red-500" />
                    ) : (
                        <ChevronDown className="h-4 w-4 text-gray-400" />
                    )}
                </div>
            </div>

            {helper && !error && (
                <p className="text-xs text-gray-500">{helper}</p>
            )}

            {error && (
                <p className="text-xs text-red-600 animate-fade-in">{error}</p>
            )}
        </div>
    );
};

export default Select;
