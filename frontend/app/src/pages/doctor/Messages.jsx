import React, { useState } from 'react';
import { Search, MessageSquare } from 'lucide-react';
import Card from '../../components/common/Card';
import Button from '../../components/common/Button';
import { mockMessages } from '../../mocks/communication';

const Messages = () => {
    const [activeMessage, setActiveMessage] = useState(mockMessages[0]);
    const [replyText, setReplyText] = useState('');

    return (
        <div className="h-[calc(100vh-140px)] flex flex-col md:flex-row gap-6">
            {/* Sidebar List */}
            <div className="w-full md:w-1/3 flex flex-col h-full bg-white dark:bg-slate-800 rounded-xl shadow-sm border border-gray-100 dark:border-slate-700 overflow-hidden">
                <div className="p-4 border-b border-gray-100 dark:border-slate-700">
                    <h2 className="text-xl font-bold text-gray-800 dark:text-slate-100 mb-4">Messages</h2>
                    <div className="relative">
                        <Search className="absolute left-3 top-2.5 text-gray-400 dark:text-slate-500 w-4 h-4" />
                        <input
                            type="text"
                            placeholder="Search conversations..."
                            className="w-full pl-9 pr-4 py-2 border border-gray-200 dark:border-slate-600 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 text-sm dark:bg-slate-700 dark:text-slate-100 dark:placeholder-slate-400"
                        />
                    </div>
                </div>

                <div className="flex-1 overflow-y-auto">
                    {mockMessages.map(msg => (
                        <div
                            key={msg.id}
                            onClick={() => setActiveMessage(msg)}
                            className={`p-4 border-b border-gray-50 dark:border-slate-700 cursor-pointer hover:bg-gray-50 dark:hover:bg-slate-700/50 transition-colors ${activeMessage?.id === msg.id ? 'bg-blue-50 dark:bg-blue-900/20 border-l-4 border-l-blue-500' : ''}`}
                        >
                            <div className="flex justify-between items-start mb-1">
                                <div className="flex items-center gap-2">
                                    <div className={`w-8 h-8 rounded-full flex items-center justify-center font-bold text-white text-xs ${msg.role === 'Patient' ? 'bg-green-500' : 'bg-blue-500'}`}>
                                        {msg.avatar}
                                    </div>
                                    <span className={`font-bold text-sm ${msg.unread ? 'text-gray-900 dark:text-slate-100' : 'text-gray-700 dark:text-slate-300'}`}>{msg.sender}</span>
                                </div>
                                <span className="text-xs text-gray-400 dark:text-slate-500">{msg.time}</span>
                            </div>
                            <p className="text-xs text-gray-500 dark:text-slate-400 pl-10 line-clamp-2">{msg.preview}</p>
                        </div>
                    ))}
                </div>
            </div>

            {/* Chat Area */}
            <Card className="flex-1 flex flex-col h-full overflow-hidden dark:bg-slate-800">
                {activeMessage ? (
                    <>
                        <div className="p-4 border-b border-gray-100 dark:border-slate-700 flex justify-between items-center">
                            <div className="flex items-center gap-3">
                                <div className={`w-10 h-10 rounded-full flex items-center justify-center font-bold text-white ${activeMessage.role === 'Patient' ? 'bg-green-500' : 'bg-blue-500'}`}>
                                    {activeMessage.avatar}
                                </div>
                                <div>
                                    <h3 className="font-bold text-gray-800 dark:text-slate-100">{activeMessage.sender}</h3>
                                    <p className="text-xs text-gray-500 dark:text-slate-400">{activeMessage.role}</p>
                                </div>
                            </div>
                            <Button variant="outline" className="p-2">
                                <MessageSquare size={18} />
                            </Button>
                        </div>

                        <div className="flex-1 p-6 overflow-y-auto bg-gray-50 dark:bg-slate-900">
                            {/* Mock Conversation */}
                            <div className="flex flex-col space-y-4">
                                <div className="self-end bg-blue-600 text-white p-3 rounded-l-lg rounded-tr-lg max-w-[80%] text-sm shadow-sm">
                                    Hello, how can I help you today?
                                </div>
                                <div className="self-start bg-white dark:bg-slate-700 border border-gray-200 dark:border-slate-600 p-3 rounded-r-lg rounded-tl-lg max-w-[80%] text-sm shadow-sm dark:text-slate-100">
                                    {activeMessage.preview}
                                </div>
                            </div>
                        </div>

                        <div className="p-4 bg-white dark:bg-slate-800 border-t border-gray-100 dark:border-slate-700">
                            <div className="flex gap-2">
                                <input
                                    type="text"
                                    className="flex-1 border border-gray-300 dark:border-slate-600 rounded-lg px-4 py-2 focus:ring-2 focus:ring-blue-500 focus:outline-none dark:bg-slate-700 dark:text-slate-100 dark:placeholder-slate-400"
                                    placeholder="Type your reply..."
                                    value={replyText}
                                    onChange={(e) => setReplyText(e.target.value)}
                                />
                                <Button>Send</Button>
                            </div>
                        </div>
                    </>
                ) : (
                    <div className="flex-1 flex flex-col items-center justify-center text-gray-400 dark:text-slate-500">
                        <MessageSquare size={48} className="mb-4 opacity-20" />
                        <p>Select a conversation to start messaging</p>
                    </div>
                )}
            </Card>
        </div>
    );
};

export default Messages;
