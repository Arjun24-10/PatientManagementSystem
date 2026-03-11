/**
 * Utility functions for formatting data
 */

/**
 * Concatenate doctor/patient first and last name
 */
export const getFullName = (user) => {
    if (!user) return 'Unknown';
    if (user.firstName && user.lastName) {
        return `${user.firstName} ${user.lastName}`;
    }
    if (user.name) return user.name;
    return 'Unknown';
};

/**
 * Format appointment date and time to readable string
 * Expects ISO format like "2024-01-15T10:30:00"
 */
export const formatAppointmentDateTime = (startTime) => {
    if (!startTime) return 'N/A';
    try {
        const date = new Date(startTime);
        return date.toLocaleDateString('en-US', {
            year: 'numeric',
            month: 'short',
            day: 'numeric',
            hour: '2-digit',
            minute: '2-digit'
        });
    } catch (err) {
        return 'Invalid Date';
    }
};

/**
 * Format just date from ISO format
 */
export const formatDate = (dateString) => {
    if (!dateString) return 'N/A';
    try {
        const date = new Date(dateString);
        return date.toLocaleDateString('en-US', {
            year: 'numeric',
            month: 'short',
            day: 'numeric'
        });
    } catch (err) {
        return 'Invalid Date';
    }
};

/**
 * Format just time from ISO format
 */
export const formatTime = (dateString) => {
    if (!dateString) return 'N/A';
    try {
        const date = new Date(dateString);
        return date.toLocaleTimeString('en-US', {
            hour: '2-digit',
            minute: '2-digit',
            hour12: true
        });
    } catch (err) {
        return 'Invalid Time';
    }
};

/**
 * Normalize status values from backend to display format
 */
export const normalizeStatus = (status) => {
    if (!status) return 'Pending';
    const normalized = status.toUpperCase();
    const statusMap = {
        'PENDING': 'Pending',
        'APPROVED': 'Approved',
        'REJECTED': 'Rejected',
        'COMPLETED': 'Completed',
        'CANCELLED': 'Cancelled',
        'CONFIRMED': 'Confirmed',
        'ACTIVE': 'Active',
        'INACTIVE': 'Inactive',
        'PRESCRIBED': 'Prescribed',
        'DISCONTINUED': 'Discontinued'
    };
    return statusMap[normalized] || status;
};

/**
 * Format blood pressure from separate values
 */
export const formatBloodPressure = (systolic, diastolic) => {
    if (!systolic || !diastolic) return 'N/A';
    return `${systolic}/${diastolic}`;
};

/**
 * Parse blood pressure string to separate values
 */
export const parseBloodPressure = (bpString) => {
    if (!bpString) return { systolic: '', diastolic: '' };
    const [systolic, diastolic] = bpString.split('/');
    return { systolic: systolic || '', diastolic: diastolic || '' };
};

/**
 * Format duration/interval for prescriptions
 */
export const formatDuration = (days) => {
    if (!days) return 'N/A';
    if (days === 1) return '1 day';
    if (days < 30) return `${days} days`;
    const weeks = Math.floor(days / 7);
    if (weeks < 4) return `${weeks} weeks`;
    const months = Math.floor(days / 30);
    return `${months} months`;
};

/**
 * Convert ISO datetime to date input format (YYYY-MM-DD)
 */
export const toDateInputFormat = (isoDate) => {
    if (!isoDate) return '';
    try {
        return isoDate.split('T')[0];
    } catch (err) {
        return '';
    }
};

/**
 * Convert ISO datetime to time input format (HH:MM)
 */
export const toTimeInputFormat = (isoDate) => {
    if (!isoDate) return '';
    try {
        const date = new Date(isoDate);
        const hours = String(date.getHours()).padStart(2, '0');
        const minutes = String(date.getMinutes()).padStart(2, '0');
        return `${hours}:${minutes}`;
    } catch (err) {
        return '';
    }
};

/**
 * Combine date and time inputs into ISO format
 */
export const toISODateTime = (date, time) => {
    if (!date || !time) return '';
    try {
        return `${date}T${time}:00`;
    } catch (err) {
        return '';
    }
};

/**
 * Format number with commas
 */
export const formatNumber = (num) => {
    if (typeof num !== 'number') return '0';
    return num.toLocaleString();
};

/**
 * Format currency
 */
export const formatCurrency = (amount, currency = 'USD') => {
    if (typeof amount !== 'number') return '$0.00';
    return new Intl.NumberFormat('en-US', {
        style: 'currency',
        currency: currency
    }).format(amount);
};
