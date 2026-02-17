import React, { useEffect } from 'react';
import { X } from 'lucide-react';

const Modal = ({ isOpen, onClose, title, children, maxWidth = 'max-w-md' }) => {
    // Close on Escape key
    useEffect(() => {
        const handleEscape = (e) => {
            if (e.key === 'Escape') onClose();
        };
        if (isOpen) document.addEventListener('keydown', handleEscape);
        return () => document.removeEventListener('keydown', handleEscape);
    }, [isOpen, onClose]);

    if (!isOpen) return null;

    return (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 dark:bg-black/70 transition-opacity p-4">
            <div className={`bg-white dark:bg-slate-800 rounded-md shadow-lg dark:shadow-slate-900/50 w-full ${maxWidth} border border-gray-200 dark:border-slate-700`}>
                {/* Header */}
                <div className="flex justify-between items-center px-4 py-3 border-b border-gray-200 dark:border-slate-700">
                    <h3 className="text-base font-semibold text-gray-800 dark:text-slate-100">{title}</h3>
                    <button
                        onClick={onClose}
                        className="w-6 h-6 flex items-center justify-center text-gray-400 dark:text-slate-500 hover:text-gray-600 dark:hover:text-slate-300 hover:bg-gray-100 dark:hover:bg-slate-700 rounded transition-colors"
                    >
                        <X size={16} />
                    </button>
                </div>

                {/* Body */}
                <div className="px-4 py-3 text-sm">
                    {children}
                </div>
            </div>
        </div>
    );
};

export default Modal;
