import React, { useState } from 'react';
import { Send, Clock, User } from 'lucide-react';

import Card from '../../components/common/Card';
import Button from '../../components/common/Button';

import Badge from '../../components/common/Badge';

const ShiftHandover = () => {
    const [notes, setNotes] = useState([
        { id: 1, author: 'Nurse Sarah', time: '07:30', shift: 'Night > Day', content: 'All patients stable. Room 302 needs monitoring for potential infection. Dr. Smith rounds at 9 AM.' },
        { id: 2, author: 'Nurse Mike', time: 'Yesterday 19:30', shift: 'Day > Night', content: 'Room 304 transferred to ICU. New admission in 306.' }
    ]);

    const [newNote, setNewNote] = useState('');

    const handleSubmit = (e) => {
        e.preventDefault();
        if (!newNote.trim()) return;

        const newEntry = {
            id: Date.now(),
            author: 'Nurse Joy (You)',
            time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
            shift: 'Day > Night',
            content: newNote
        };

        setNotes([newEntry, ...notes]);
        setNewNote('');
    };

    return (
        <div className="space-y-6 max-w-4xl mx-auto">
            <div className="flex justify-between items-center">
                <div>
                    <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Shift Handover Notes</h1>
                    <p className="text-gray-500">Document and review shift summaries.</p>
                </div>
            </div>

            <Card className="p-6">
                <form onSubmit={handleSubmit}>
                    <h3 className="text-lg font-semibold mb-3">Add New Handover Note</h3>
                    <textarea
                        className="w-full rounded-md border border-gray-300 dark:border-slate-600 dark:bg-slate-800 dark:text-white p-3 focus:ring-2 focus:ring-blue-500 focus:border-transparent min-h-[120px]"
                        placeholder="Enter handover details for the next shift..."
                        value={newNote}
                        onChange={(e) => setNewNote(e.target.value)}
                    ></textarea>
                    <div className="flex justify-between items-center mt-3">
                        <span className="text-sm text-gray-500">Visible to incoming shift staff only.</span>
                        <Button type="submit" variant="primary" disabled={!newNote.trim()}>
                            <Send className="w-4 h-4 mr-2" />
                            Submit Note
                        </Button>
                    </div>
                </form>
            </Card>

            <div className="space-y-4">
                <h3 className="text-lg font-semibold text-gray-700 dark:text-slate-200">Recent Handovers</h3>
                <div className="relative border-l-2 border-gray-200 dark:border-slate-700 ml-3 space-y-8 pb-4">
                    {notes.map((note) => (
                        <div key={note.id} className="relative pl-8">
                            <div className="absolute -left-[9px] top-0 w-4 h-4 rounded-full bg-blue-500 border-4 border-white dark:border-slate-900"></div>

                            <Card className="p-4">
                                <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center mb-3 gap-2">
                                    <div className="flex items-center gap-3">
                                        <div className="font-semibold text-gray-900 dark:text-white flex items-center">
                                            <User className="w-4 h-4 mr-1 text-gray-500" />
                                            {note.author}
                                        </div>
                                        <div className="text-sm text-gray-500 flex items-center">
                                            <Clock className="w-3 h-3 mr-1" />
                                            {note.time}
                                        </div>
                                    </div>
                                    <Badge type="blue" variant="soft">{note.shift}</Badge>
                                </div>
                                <div className="text-gray-700 dark:text-slate-300 whitespace-pre-line">
                                    {note.content}
                                </div>
                            </Card>
                        </div>
                    ))}
                </div>
            </div>
        </div>
    );
};

export default ShiftHandover;
