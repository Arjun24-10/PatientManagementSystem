import React, { useState, useEffect } from 'react';
import { Send, Clock, User } from 'lucide-react';

import Card from '../../components/common/Card';
import Button from '../../components/common/Button';

import Badge from '../../components/common/Badge';
import api from '../../services/api';

const ShiftHandover = () => {
    const [fromPreviousShift, setFromPreviousShift] = useState([]);
    const [forNextShift, setForNextShift] = useState([]);
    const [isLoading, setIsLoading] = useState(true);
    const [isSaving, setIsSaving] = useState(false);
    const [error, setError] = useState(null);

    const [newNote, setNewNote] = useState('');

    useEffect(() => {
        const fetchNotes = async () => {
            try {
                setIsLoading(true);
                const data = await api.nurse.getHandoverNotes();
                if (data) {
                    setFromPreviousShift(data.fromPreviousShift || []);
                    setForNextShift(data.forNextShift || []);
                }
            } catch (err) {
                console.error('Failed to load handover notes:', err);
                setError('Failed to load handover notes.');
            } finally {
                setIsLoading(false);
            }
        };
        fetchNotes();
    }, []);

    const handleSubmit = async (e) => {
        e.preventDefault();
        if (!newNote.trim()) return;

        try {
            setIsSaving(true);
            setError(null);
            const saved = await api.nurse.saveHandoverNote({
                content: newNote,
                type: 'general',
                priority: 'normal',
                direction: 'FOR_NEXT',
            });
            if (saved) {
                setForNextShift(prev => [saved, ...prev]);
            }
            setNewNote('');
        } catch (err) {
            console.error('Failed to save handover note:', err);
            setError('Failed to save note. Please try again.');
        } finally {
            setIsSaving(false);
        }
    };

    const formatNoteAuthor = (note) => {
        if (note.author) {
            return note.author.email || note.author.username || 'Nurse';
        }
        return 'Nurse';
    };

    const formatNoteTime = (note) => {
        if (!note.timestamp) return '';
        return new Date(note.timestamp).toLocaleString([], {
            month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit',
        });
    };

    const allNotes = [
        ...fromPreviousShift.map(n => ({ ...n, shiftLabel: 'Previous → Current' })),
        ...forNextShift.map(n => ({ ...n, shiftLabel: 'Current → Next' })),
    ].sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));

    return (
        <div className="space-y-6 max-w-4xl mx-auto">
            <div className="flex justify-between items-center">
                <div>
                    <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Shift Handover Notes</h1>
                    <p className="text-gray-500">Document and review shift summaries.</p>
                </div>
            </div>

            {error && (
                <div className="bg-red-50 dark:bg-red-900/10 p-3 rounded-md border border-red-100 dark:border-red-900/20 text-sm text-red-700 dark:text-red-300">
                    {error}
                </div>
            )}

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
                        <Button type="submit" variant="primary" disabled={!newNote.trim() || isSaving}>
                            <Send className="w-4 h-4 mr-2" />
                            {isSaving ? 'Saving...' : 'Submit Note'}
                        </Button>
                    </div>
                </form>
            </Card>

            <div className="space-y-4">
                <h3 className="text-lg font-semibold text-gray-700 dark:text-slate-200">Recent Handovers</h3>
                {isLoading ? (
                    <div className="text-center py-8 text-gray-500">Loading handover notes...</div>
                ) : allNotes.length === 0 ? (
                    <div className="text-center py-8 text-gray-500">No handover notes found.</div>
                ) : (
                    <div className="relative border-l-2 border-gray-200 dark:border-slate-700 ml-3 space-y-8 pb-4">
                        {allNotes.map((note) => (
                            <div key={note.id} className="relative pl-8">
                                <div className="absolute -left-[9px] top-0 w-4 h-4 rounded-full bg-blue-500 border-4 border-white dark:border-slate-900"></div>

                                <Card className="p-4">
                                    <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center mb-3 gap-2">
                                        <div className="flex items-center gap-3">
                                            <div className="font-semibold text-gray-900 dark:text-white flex items-center">
                                                <User className="w-4 h-4 mr-1 text-gray-500" />
                                                {formatNoteAuthor(note)}
                                            </div>
                                            <div className="text-sm text-gray-500 flex items-center">
                                                <Clock className="w-3 h-3 mr-1" />
                                                {formatNoteTime(note)}
                                            </div>
                                        </div>
                                        <Badge type="blue" variant="soft">{note.shiftLabel}</Badge>
                                    </div>
                                    <div className="text-gray-700 dark:text-slate-300 whitespace-pre-line">
                                        {note.content}
                                    </div>
                                </Card>
                            </div>
                        ))}
                    </div>
                )}
            </div>
        </div>
    );
};

export default ShiftHandover;
