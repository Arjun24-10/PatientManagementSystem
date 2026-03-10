# Lab Technician Integration Issues - UPDATED (Frontend + Backend Audit)
**Last Updated**: March 9, 2026  
**Severity Level**: 🟠 MAJOR - Dashboard/Orders Working, Upload Needs JSON Format Fix

---

## Executive Summary - CORRECTED

Backend API survey completed. **Good news**: Lab endpoints exist and mostly work. **Issue to fix**:
- ✅ Dashboard - Backend endpoint ready, needs frontend connection
- ✅ Orders List - Backend endpoint ready, needs frontend connection
- ✅ Update Status - Backend endpoint ready, needs frontend connection
- ⚠️ **Upload Results - Backend ready but expects JSON, not FormData** (Frontend needs fix)
- ❌ File Retrieval - No endpoint to download uploaded files
- ❌ Lab Order Creation - Doctors can't order tests (not needed right now)

---

## ✅ WORKING - Backend Endpoints Exist

### Endpoint #1: GET /api/lab-technician/dashboard - Dashboard Stats ✅
**Status**: BACKEND READY - Frontend Dashboard.jsx needs to call it

**What It Returns** (From LabTechnicianService.getDashboardOverview):
```json
{
  "pending": 5,
  "collected": 3,
  "resultsPending": 2,
  "completed": 42,
  "recentActivity": [
    {
      "testId": 1,
      "patient": { "firstName": "John", "lastName": "Doe" },
      "orderedBy": { "email": "doctor@email.com" },
      "testName": "CBC",
      "testCategory": "Hematology",
      "resultValue": "...",
      "status": "Completed",
      "orderDate": "2026-03-09T10:00:00"
    }
  ]
}
```

**Current Implementation**: Dashboard.jsx (Lines 8-17) uses mockLabOrders/mockLabActivity  
**Frontend Fix Required**: Call `api.labTechnician.getDashboard()` on mount

---

### Endpoint #2: GET /api/lab-technician/orders - Get All Orders ✅
**Status**: BACKEND READY - Frontend Orders.jsx needs to call it

**Query Parameters**:
- `?status=Pending` - Filter by status (optional)  
- No pagination currently (loads all orders)

**What It Returns**: Array of LabTestDTO objects
```json
[
  {
    "testId": 1,
    "patientName": "John Doe",
    "gender": "M",
    "profileId": 1,
    "orderedByDoctor": "doctor@hospital.com",
    "orderedById": 5,
    "testName": "Complete Blood Count",
    "testCategory": "Hematology",
    "resultValue": null,
    "unit": "cells/μL",
    "referenceRange": "4.5-11.0",
    "remarks": null,
    "status": "Pending",
    "fileUrl": null
  }
]
```

**Current Implementation**: Orders.jsx (Lines 17-31) filters mockLabOrders  
**Frontend Fix Required**: Call `api.labTechnician.getOrders(statusFilter)` on mount/filter change

---

### Endpoint #3: PUT /api/lab-technician/orders/{testId}/status - Update Order Status ✅
**Status**: BACKEND READY - Orders.jsx needs to call it

**Request Body**:
```json
{
  "status": "Collected"    // Can be: Pending, Collected, Processing, Results Pending, Completed, Cancelled
}
```

**What It Returns**: Updated LabTestDTO

**Current Implementation**: Orders.jsx doesn't update status (no API call exists)  
**Frontend Fix Required**: Backend API service call on status button click

---

### Endpoint #4: PUT /api/lab-technician/orders/{testId}/upload - Upload Results ✅
**Status**: BACKEND READY - But expects JSON not FormData

**IMPORTANT**: Request body must be JSON, not multipart/form-data:
```json
PUT /api/lab-technician/orders/{testId}/upload
{
  "resultValue": "98.6",           // Text/numeric result
  "remarks": "Normal reading",     // Optional notes
  "fileUrl": "/path/to/file.pdf"   // Optional: URL string to already-uploaded file
}
```

**What It Returns**: Updated LabTestDTO with status="Completed"

**Current Implementation**: UploadResults.jsx (Lines 16-25) tries to send FormData (wrong format!)  
**Frontend Fix Required**: 
1. If sending text results only: Send JSON with resultValue
2. If uploading file: First send file to file service, get URL, then send URL in JSON

---

## ⚠️ PARTIAL - Needs Frontend Format Fix

### ISSUE #LB1: File Upload Format Mismatch ⚠️
**Severity**: MAJOR  
**Current**: UploadResults.jsx sends FormData (wrong)  
**Backend Expects**: JSON with either resultValue or fileUrl (string)

**What's Wrong**:
```javascript
// CURRENT - WRONG FORMAT (UploadResults.jsx lines 16-25):
const handleSubmit = (e) => {
    const formData = new FormData();           // ❌ WRONG
    formData.append('file', file);             // ❌ Backend doesn't accept this
    formData.append('selectedOrder', selectedOrder);
    // Backend returns 400 Bad Request
};
```

**Fix Required** - Send JSON instead:
```javascript
// CORRECT FORMAT:
const handleSubmit = async (e) => {
    e.preventDefault();
    try {
        // Option 1: Text results only
        if (testValues && !file) {
            await api.labTechnician.uploadResults(
                selectedOrder,
                testValues,  // resultValue
                remarks,     // remarks
                null         // no file
            );
        } 
        // Option 2: File results (file URL string, not FormData!)
        else if (file) {
            // Would need to upload file elsewhere first and get URL
            const fileUrl = `/uploads/lab-results/${file.name}`;  // Example
            await api.labTechnician.uploadResults(
                selectedOrder,
                null,        // no text value
                remarks,
                fileUrl      // pass URL string, not file object
            );
        }
    } catch (err) {
        console.error('Failed to upload', err);
    }
};
```

**Lines**: Replace handleSubmit function (Lines 16-25)

---

## ❌ NOT WORKING - Backend Missing

### ISSUE #LB2: No File Retrieval Endpoint ❌
**Severity**: MAJOR - Cannot view uploaded files  
**Status**: BLOCKED (No backend endpoint exists)

**Missing**: No endpoint to download/view uploaded result files  
**What Would Be Needed**: `GET /api/lab-technician/orders/{testId}/results/file`

**Impact**: Doctors/patients cannot see uploaded PDFs or images  
**Cannot Fix**: Without backend endpoint

---

### ISSUE #LB3: No Lab Order Creation Endpoint ❌
**Severity**: LOW (Doctor feature, not lab) - Doctors can't order tests  
**Status**: BLOCKED (No backend endpoint exists)

**Missing**: Doctors can't create lab orders, so nothing for lab tech to process  
**Note**: May be intentional - orders might be created through EMR/different system

---

## 🟠 MAJOR ISSUES - Frontend Fixes Needed

### FIX #LF1: lab/Dashboard.jsx - Connect to Backend ✅ (RESOLVED)
**Severity**: MAJOR  
**Current**: Resolved
**Fix Needed**: Call `api.labTechnician.getDashboard()` on mount

**Implementation**:
```javascript
const [dashboard, setDashboard] = useState({
    pending: 0,
    collected: 0,
    resultsPending: 0,
    completed: 0,
    recentActivity: []
});
const [isLoading, setIsLoading] = useState(false);

useEffect(() => {
    const fetchDashboard = async () => {
        try {
            setIsLoading(true);
            const data = await api.labTechnician.getDashboard();
            setDashboard(data);
        } catch (err) {
            console.error('Failed to load dashboard', err);
        } finally {
            setIsLoading(false);
        }
    };
    fetchDashboard();
}, []);

// Use dashboard.pending, dashboard.collected, etc. instead of mockLabOrders
const pendingCount = dashboard.pending;
const collectedCount = dashboard.collected;
const resultsPendingCount = dashboard.resultsPending;
const completedCount = dashboard.completed;
```

**Lines**: Replace lines 8-17

---

### FIX #LF2: lab/Orders.jsx - Connect to Backend ✅ (RESOLVED)
**Severity**: MAJOR  
**Current**: Resolved
**Fix Needed**: Call `api.labTechnician.getOrders(statusFilter)` and handle status updates

**Implementation**:
```javascript
const [orders, setOrders] = useState([]);
const [isLoading, setIsLoading] = useState(false);

useEffect(() => {
    const fetchOrders = async () => {
        try {
            setIsLoading(true);
            const status = statusFilter === 'All' ? null : statusFilter;
            const data = await api.labTechnician.getOrders(status);
            setOrders(data || []);
        } catch (err) {
            console.error('Failed to load orders', err);
        } finally {
            setIsLoading(false);
        }
    };
    fetchOrders();
}, [statusFilter]); // Re-fetch when filter changes

// Add handler to update status
const handleStatusUpdate = async (testId, newStatus) => {
    try {
        await api.labTechnician.updateOrderStatus(testId, newStatus);
        // Refresh orders
        const status = statusFilter === 'All' ? null : statusFilter;
        const data = await api.labTechnician.getOrders(status);
        setOrders(data);
    } catch (err) {
        console.error('Failed to update status', err);
    }
};
```

**Lines**: Replace lines 17-31 and update filter change handler

---

### FIX #LF3: lab/UploadResults.jsx - Fix Format & Connect to Backend ✅ (RESOLVED)
**Severity**: CRITICAL  
**Current**: Resolved 
**Fix Needed**: Send JSON payload via api.labTechnician.uploadResults()

**Implementation**:
```javascript
const handleSubmit = async (e) => {
    e.preventDefault();
    
    // Validate: need either test values OR file
    if (!testValues && !file) {
        setStatus('error');
        return;
    }
    
    try {
        setStatus('uploading');
        
        // Send JSON payload to backend
        await api.labTechnician.uploadResults(
            selectedOrder,
            testValues || null,     // resultValue (string/numeric)
            '', // remarks (empty if not provided)
            null                    // fileUrl (null - file upload not supported without backend changes)
        );
        
        setStatus('success');
        
        // Reset form after success
        setTimeout(() => {
            setSelectedOrder('');
            setTestValues('');
            setFile(null);
            setStatus('idle');
        }, 2000);
        
    } catch (err) {
        console.error('Upload failed:', err);
        setStatus('error');
    }
};
```

**Lines**: Replace handleSubmit function (Lines 16-25)

---

### FIX #LF4: lab/Orders.jsx & UploadResults.jsx - Map Status Values ⚠️
**Severity**: MINOR - Status values may not match  
**Current**: Frontend expects certain status strings  
**Fix Needed**: Ensure status values match between frontend display and backend

**Required Standardization**:
```javascript
// Backend returns these status values:
const VALID_STATUSES = ['Pending', 'Collected', 'Processing', 'Results Pending', 'Completed', 'Cancelled'];

// Frontend should use capitalized values with spaces
const getStatusType = (status) => {
    switch (status) {
        case 'Pending': return 'yellow';
        case 'Collected': return 'blue';
        case 'Processing': return 'orange';
        case 'Results Pending': return 'indigo';
        case 'Completed': return 'green';
        case 'Cancelled': return 'red';
        default: return 'gray';
    }
};
```

**Lines**: Already correct in Orders.jsx (Lines 43-51), verify UploadResults.jsx statusfilter matches

---

## 📋 Frontend Integration Checklist

- [x] **FIX #LF1** - lab/Dashboard.jsx calls api.labTechnician.getDashboard() (10 min)
- [x] **FIX #LF2** - lab/Orders.jsx calls api.labTechnician.getOrders() and updateOrderStatus() (15 min)
- [x] **FIX #LF3** - lab/UploadResults.jsx sends JSON not FormData (10 min)
- [x] **FIX #LF4** - Verify status value matching (5 min)
- [ ] **BLOCKED** - File download (needs backend endpoint)
- [ ] **BLOCKED** - Lab order creation (needs backend endpoint)

**Total Frontend Fixes**: ~40 minutes  
**Blocked (Backend Required)**: File download endpoint

---

## Testing After Fixes

```bash
# Login as lab technician
# Test 1: Dashboard shows real pending/collected/completed counts
# Test 2: Orders page populated from API  
# Test 3: Can filter orders by status
# Test 4: Upload results form submits successfully
# Test 5: Uploaded results appear in order list as "Completed"
# Test 6: Cannot download uploaded files yet (needs backend endpoint)
```
