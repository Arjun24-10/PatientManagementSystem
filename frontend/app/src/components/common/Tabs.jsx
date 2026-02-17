import React, { useState } from 'react';

const Tabs = ({ tabs, defaultTab, onChange, className = '' }) => {
    const [activeTab, setActiveTab] = useState(defaultTab || tabs[0]?.id);

    const handleTabChange = (id) => {
        setActiveTab(id);
        onChange?.(id);
    };

    return (
        <div className={className}>
            <div className="border-b border-gray-200">
                <nav className="-mb-px flex space-x-8" aria-label="Tabs">
                    {tabs.map((tab) => {
                        const isActive = activeTab === tab.id;
                        return (
                            <button
                                key={tab.id}
                                onClick={() => handleTabChange(tab.id)}
                                className={`
                                    whitespace-nowrap py-4 px-1 border-b-2 font-medium text-sm transition-colors duration-200
                                    ${isActive
                                        ? 'border-primary text-primary'
                                        : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
                                    }
                                `}
                                aria-current={isActive ? 'page' : undefined}
                            >
                                {tab.label}
                            </button>
                        );
                    })}
                </nav>
            </div>
            <div className="mt-4">
                {tabs.find((tab) => tab.id === activeTab)?.content}
            </div>
        </div>
    );
};

export default Tabs;
