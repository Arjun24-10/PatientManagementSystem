import React, { useState, useEffect } from 'react';
import { Clock, AlertTriangle } from 'lucide-react';
import Modal from '../common/Modal';
import Button from '../common/Button';

const SessionTimeout = ({
    isActive,
    onLogout,
    onExtend,
    warningTime = 60 // seconds to show warning before logout
}) => {
    const [timeLeft, setTimeLeft] = useState(warningTime);

    useEffect(() => {
        if (!isActive) return;

        setTimeLeft(warningTime);
        const timer = setInterval(() => {
            setTimeLeft((prev) => {
                if (prev <= 1) {
                    clearInterval(timer);
                    onLogout();
                    return 0;
                }
                return prev - 1;
            });
        }, 1000);

        return () => clearInterval(timer);
    }, [isActive, onLogout, warningTime]);

    if (!isActive) return null;

    return (
        <Modal
            isOpen={isActive}
            onClose={() => { }} // Force user to choose an action
            title="Session Timeout Warning"
            icon={AlertTriangle}
            variant="warning"
        >
            <div className="text-center space-y-4">
                <div className="flex justify-center">
                    <div className="w-16 h-16 bg-amber-100 rounded-full flex items-center justify-center animate-pulse">
                        <Clock className="w-8 h-8 text-amber-600" />
                    </div>
                </div>

                <p className="text-gray-600 dark:text-slate-300">
                    Your session will expire in <span className="font-bold text-gray-900 dark:text-white">{timeLeft} seconds</span> due to inactivity.
                </p>

                <p className="text-sm text-gray-500 dark:text-slate-400">
                    Would you like to extend your session or log out?
                </p>

                <div className="flex gap-3 justify-center pt-2">
                    <Button
                        variant="outline"
                        onClick={onLogout}
                        className="w-full sm:w-auto"
                    >
                        Log Out
                    </Button>
                    <Button
                        variant="primary"
                        onClick={onExtend}
                        className="w-full sm:w-auto"
                    >
                        Extend Session
                    </Button>
                </div>
            </div>
        </Modal>
    );
};

export default SessionTimeout;
