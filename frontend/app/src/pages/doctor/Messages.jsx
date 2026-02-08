import React, { useState } from 'react';
import { Search, PenSquare, MessageSquare } from 'lucide-react';
import Card from '../../components/common/Card';
import Button from '../../components/common/Button';
import Input from '../../components/common/Input';
import { mockMessages } from '../../mocks/communication';

const Messages = () => {
    const [activeMessage, setActiveMessage] = useState(mockMessages[0]);
    const [replyText, setReplyText] = useState('');

    return (
        <div className="h-[calc(100vh-140px)] flex flex-col md:flex-row gap-6">
            {/* Sidebar List */}
            <div className="w-full md:w-1/3 flex flex-col h-full bg-white rounded-xl shadow-sm border border-gray-100 overflow-hidden">
                <div className="p-4 border-b border-gray-100">
                    <h2 className="text-xl font-bold text-gray-800 mb-4">Messages</h2>
                    <div className="relative">
                        <Search className="absolute left-3 top-2.5 text-gray-400 w-4 h-4" />
                        <input
                            type="text"
                            placeholder="Search conversations..."
                            className="w-full pl-9 pr-4 py-2 border border-gray-200 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 text-sm"
                        />
                    </div>
                </div>

                <div className="flex-1 overflow-y-auto">
                    {mockMessages.map(msg => (
                        <div
                            key={msg.id}
                            onClick={() => setActiveMessage(msg)}
                            className={`p-4 border-b border-gray-50 cursor-pointer hover:bg-gray-50 transition-colors ${activeMessage?.id === msg.id ? 'bg-blue-50 border-l-4 border-l-blue-500' : ''}`}
                        >
                            <div className="flex justify-between items-start mb-1">
                                <div className="flex items-center gap-2">
                                    <div className={`w-8 h-8 rounded-full flex items-center justify-center font-bold text-white text-xs ${msg.role === 'Patient' ? 'bg-green-500' : 'bg-blue-500'}`}>
                                        {msg.avatar}
                                    </div>
                                    <span className={`font-bold text-sm ${msg.unread ? 'text-gray-900' : 'text-gray-700'}`}>{msg.sender}</span>
                                </div>
                                <span className="text-xs text-gray-400">{msg.time}</span>
                            </div>
                            <p className="text-xs text-gray-500 pl-10 line-clamp-2">{msg.preview}</p>
                        </div>
                    ))}
                </div>
            </div>

            {/* Chat Area */}
            <Card className="flex-1 flex flex-col h-full overflow-hidden">
                {activeMessage ? (
                    <>
                        <div className="p-4 border-b border-gray-100 flex justify-between items-center">
                            <div className="flex items-center gap-3">
                                <div className={`w-10 h-10 rounded-full flex items-center justify-center font-bold text-white ${activeMessage.role === 'Patient' ? 'bg-green-500' : 'bg-blue-500'}`}>
                                    {activeMessage.avatar}
                                </div>
                                <div>
                                    <h3 className="font-bold text-gray-800">{activeMessage.sender}</h3>
                                    <p className="text-xs text-gray-500">{activeMessage.role}</p>
                                </div>
                            </div>
                            <Button variant="outline" className="p-2">
                                <MessageSquare size={18} />
                            </Button>
                        </div>

                        <div className="flex-1 p-6 overflow-y-auto bg-gray-50">
                            {/* Mock Conversation */}
                            <div className="flex flex-col space-y-4">
                                <div className="self-end bg-blue-600 text-white p-3 rounded-l-lg rounded-tr-lg max-w-[80%] text-sm shadow-sm">
                                    Hello, how can I help you today?
                                </div>
                                <div className="self-start bg-white border border-gray-200 p-3 rounded-r-lg rounded-tl-lg max-w-[80%] text-sm shadow-sm">
                                    {activeMessage.preview}
                                </div>
                            </div>
                        </div>

                        <div className="p-4 bg-white border-t border-gray-100">
                            <div className="flex gap-2">
                                <input
                                    type="text"
                                    className="flex-1 border border-gray-300 rounded-lg px-4 py-2 focus:ring-2 focus:ring-blue-500 focus:outline-none"
                                    placeholder="Type your reply..."
                                    value={replyText}
                                    onChange={(e) => setReplyText(e.target.value)}
                                />
                                <Button>Send</Button>
                            </div>
                        </div>
                    </>
                ) : (
                    <div className="flex-1 flex flex-col items-center justify-center text-gray-400">
                        <MessageSquare size={48} className="mb-4 opacity-20" />
                        <p>Select a conversation to start messaging</p>
                    </div>
                )}
            </Card>
        </div>
    );
};

export default Messages;
