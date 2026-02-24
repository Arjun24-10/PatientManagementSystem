import React, { forwardRef } from 'react';
import { Check, Minus } from 'lucide-react';

const Checkbox = forwardRef(({ id, label, checked, indeterminate, disabled, onChange, className = '' }, ref) => {
    return (
        <div className={`flex items-start ${className}`}>
            <div className="flex items-center h-5">
                <button
                    type="button"
                    role="checkbox"
                    aria-checked={indeterminate ? 'mixed' : checked}
                    disabled={disabled}
                    onClick={() => !disabled && onChange?.(!checked)}
                    ref={ref}
                    className={`
                        flex items-center justify-center w-4 h-4 rounded border transition-colors duration-200 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary
                        ${checked || indeterminate
                            ? 'bg-primary border-primary text-white'
                            : 'bg-white border-gray-300 hover:border-gray-400'
                        }
                        ${disabled ? 'opacity-50 cursor-not-allowed bg-gray-100' : 'cursor-pointer'}
                    `}
                >
                    {checked && !indeterminate && <Check className="w-3 h-3" strokeWidth={3} />}
                    {indeterminate && <Minus className="w-3 h-3" strokeWidth={3} />}
                </button>
            </div>
            {label && (
                <div className="ml-2 text-sm">
                    <label
                        htmlFor={id}
                        className={`font-medium ${disabled ? 'text-gray-400' : 'text-gray-700 cursor-pointer'}`}
                        onClick={() => !disabled && onChange?.(!checked)}
                    >
                        {label}
                    </label>
                </div>
            )}
        </div>
    );
});

Checkbox.displayName = 'Checkbox';

export default Checkbox;
