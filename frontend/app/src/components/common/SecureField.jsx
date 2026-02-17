import React, { useState } from 'react';
import { Eye, EyeOff, Lock } from 'lucide-react';
import Button from './Button';

const SecureField = ({
    value,
    label,
    className = '',
    maskChar = '•'
}) => {
    const [revealed, setRevealed] = useState(false);

    const displayValue = revealed ? value : maskChar.repeat(value?.length || 8); // Default length for unknown

    return (
        <div className={`flex flex-col ${className}`}>
            {label && (
                <span className="text-xs font-medium text-gray-500 mb-1 flex items-center gap-1">
                    <Lock className="w-3 h-3" />
                    {label}
                </span>
            )}
            <div className="flex items-center justify-between p-2 bg-gray-50 rounded border border-gray-200">
                <code className="text-sm font-mono text-gray-700 truncate mr-2 select-all">
                    {displayValue}
                </code>
                <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => setRevealed(!revealed)}
                    className="h-6 w-6 p-0 hover:bg-gray-200"
                    aria-label={revealed ? "Hide value" : "Show value"}
                >
                    {revealed ? <EyeOff className="w-3 h-3" /> : <Eye className="w-3 h-3" />}
                </Button>
            </div>
        </div>
    );
};

export default SecureField;
