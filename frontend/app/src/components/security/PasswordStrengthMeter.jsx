import React from 'react';

const PasswordStrengthMeter = ({ password }) => {
    const getStrength = (pass) => {
        let strength = 0;
        if (pass.length > 5) strength += 1;
        if (pass.length > 10) strength += 1;
        if (/[A-Z]/.test(pass)) strength += 1;
        if (/[0-9]/.test(pass)) strength += 1;
        if (/[^A-Za-z0-9]/.test(pass)) strength += 1;
        return strength;
    };

    const strength = getStrength(password);

    const getColor = (s) => {
        if (s === 0) return 'bg-gray-200';
        if (s < 3) return 'bg-red-500';
        if (s < 4) return 'bg-amber-500';
        return 'bg-emerald-500';
    };

    const getLabel = (s) => {
        if (s === 0) return 'Enter password';
        if (s < 3) return 'Weak';
        if (s < 4) return 'Medium';
        return 'Strong';
    };

    return (
        <div className="mt-2 text-xs">
            <div className="flex justify-between mb-1">
                <span className="text-gray-500 dark:text-slate-400">Password strength</span>
                <span className={`font-medium ${strength < 3 ? 'text-red-500' : strength < 4 ? 'text-amber-500' : 'text-emerald-500'
                    }`}>
                    {getLabel(strength)}
                </span>
            </div>
            <div className="flex gap-1 h-1">
                {[...Array(4)].map((_, i) => (
                    <div
                        key={i}
                        className={`h-full rounded-full flex-1 transition-colors duration-300 ${i < strength ? getColor(strength) : 'bg-gray-200 dark:bg-slate-700'
                            }`}
                    />
                ))}
            </div>
            <ul className="mt-2 space-y-1 text-gray-400">
                <li className={`flex items-center gap-1.5 ${password.length >= 8 ? 'text-emerald-600 dark:text-emerald-400' : ''}`}>
                    <div className={`w-1 h-1 rounded-full ${password.length >= 8 ? 'bg-emerald-500' : 'bg-gray-300'}`} />
                    Min. 8 characters
                </li>
                <li className={`flex items-center gap-1.5 ${/[A-Z]/.test(password) && /[0-9]/.test(password) ? 'text-emerald-600 dark:text-emerald-400' : ''}`}>
                    <div className={`w-1 h-1 rounded-full ${/[A-Z]/.test(password) && /[0-9]/.test(password) ? 'bg-emerald-500' : 'bg-gray-300'}`} />
                    Uppercase & Number
                </li>
            </ul>
        </div>
    );
};

export default PasswordStrengthMeter;
