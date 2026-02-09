import React, { useState } from 'react';
import { Upload, CheckCircle } from 'lucide-react';
import Card from '../../components/common/Card';
import Button from '../../components/common/Button';
import { mockLabOrders } from '../../mocks/labOrders';

const UploadResults = () => {
    const [selectedOrder, setSelectedOrder] = useState('');
    const [file, setFile] = useState(null);
    const [testValues, setTestValues] = useState('');
    const [status, setStatus] = useState('idle'); // idle, uploading, success, error

    const handleFileChange = (e) => {
        if (e.target.files && e.target.files[0]) {
            setFile(e.target.files[0]);
        }
    };

    const handleSubmit = (e) => {
        e.preventDefault();
        setStatus('uploading');
        // Mock upload delay
        setTimeout(() => {
            setStatus('success');
            // Reset after 3 seconds
            setTimeout(() => setStatus('idle'), 3000);
        }, 1500);
    };

    return (
        <div className="max-w-2xl mx-auto space-y-8">
            <div>
                <h2 className="text-2xl font-bold text-gray-800 dark:text-slate-100">Upload Lab Results</h2>
                <p className="text-gray-500 dark:text-slate-400">Attach files or enter manual results for lab orders.</p>
            </div>

            <Card className="p-8 dark:bg-slate-800">
                <form onSubmit={handleSubmit} className="space-y-6">
                    <div>
                        <label className="block text-sm font-medium text-gray-700 dark:text-slate-300 mb-2">Select Lab Order</label>
                        <select
                            className="w-full p-3 border border-gray-200 dark:border-slate-600 rounded-xl focus:ring-2 focus:ring-brand-medium focus:outline-none bg-white dark:bg-slate-800 text-gray-900 dark:text-slate-100"
                            value={selectedOrder}
                            onChange={(e) => setSelectedOrder(e.target.value)}
                            required
                        >
                            <option value="">-- Select Order --</option>
                            {mockLabOrders.filter(o => o.status !== 'Completed').map(order => (
                                <option key={order.id} value={order.id}>
                                    {order.id} - {order.patientName} ({order.testType})
                                </option>
                            ))}
                        </select>
                    </div>

                    <div className="border-t border-gray-100 dark:border-slate-700 pt-6"></div>

                    <div>
                        <label className="block text-sm font-medium text-gray-700 dark:text-slate-300 mb-2">Upload Report File (PDF/Image)</label>
                        <div className="mt-1 flex justify-center px-6 pt-5 pb-6 border-2 border-gray-300 dark:border-slate-600 border-dashed rounded-xl hover:bg-gray-50 dark:hover:bg-slate-700/50 transition-colors cursor-pointer relative">
                            <div className="space-y-1 text-center">
                                <Upload className="mx-auto h-12 w-12 text-gray-400 dark:text-slate-500" />
                                <div className="flex text-sm text-gray-600 dark:text-slate-400">
                                    <label htmlFor="file-upload" className="relative cursor-pointer bg-white dark:bg-slate-800 rounded-md font-medium text-brand-medium hover:text-brand-deep focus-within:outline-none">
                                        <span>Upload a file</span>
                                        <input id="file-upload" name="file-upload" type="file" className="sr-only" onChange={handleFileChange} accept=".pdf,.png,.jpg,.jpeg" />
                                    </label>
                                    <p className="pl-1">or drag and drop</p>
                                </div>
                                <p className="text-xs text-gray-500 dark:text-slate-500">PDF, PNG, JPG up to 10MB</p>
                            </div>
                            {file && (
                                <div className="absolute inset-0 bg-green-50/90 dark:bg-green-900/30 flex flex-col items-center justify-center rounded-xl">
                                    <CheckCircle className="text-green-600 dark:text-green-400 w-8 h-8 mb-2" />
                                    <p className="text-sm font-medium text-green-800 dark:text-green-200">{file.name}</p>
                                    <button type="button" onClick={() => setFile(null)} className="text-xs text-red-500 dark:text-red-400 mt-2 hover:underline">Remove</button>
                                </div>
                            )}
                        </div>
                    </div>

                    <div className="relative">
                        <div className="absolute inset-0 flex items-center" aria-hidden="true">
                            <div className="w-full border-t border-gray-300 dark:border-slate-600"></div>
                        </div>
                        <div className="relative flex justify-center">
                            <span className="px-2 bg-white dark:bg-slate-800 text-sm text-gray-500 dark:text-slate-400">OR</span>
                        </div>
                    </div>

                    <div>
                        <label className="block text-sm font-medium text-gray-700 dark:text-slate-300 mb-2">Manual Result Entry</label>
                        <textarea
                            rows="4"
                            className="w-full p-3 border border-gray-200 dark:border-slate-600 rounded-xl focus:ring-2 focus:ring-brand-medium focus:outline-none bg-white dark:bg-slate-800 text-gray-900 dark:text-slate-100 dark:placeholder-slate-500"
                            placeholder="Enter test values, reference ranges, and observations..."
                            value={testValues}
                            onChange={(e) => setTestValues(e.target.value)}
                        />
                    </div>

                    <div className="pt-4">
                        <Button
                            type="submit"
                            disabled={!selectedOrder || (!file && !testValues) || status === 'uploading'}
                            className="w-full justify-center"
                        >
                            {status === 'uploading' ? 'Uploading...' : 'Submit Results'}
                        </Button>
                    </div>

                    {status === 'success' && (
                        <div className="p-4 rounded-lg bg-green-50 dark:bg-green-900/20 text-green-700 dark:text-green-300 flex items-center animate-fade-in">
                            <CheckCircle className="w-5 h-5 mr-2" />
                            Results uploaded successfully! Doctor has been notified.
                        </div>
                    )}
                </form>
            </Card>
        </div>
    );
};

export default UploadResults;
