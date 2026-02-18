# Integration Testing Architecture

## 🏗️ How Everything Fits Together

```
┌─────────────────────────────────────────────────────────────┐
│                     YOUR REACT APP                          │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  │
│  │  Login   │  │ Patient  │  │  Doctor  │  │  Nurse   │  │
│  │   Page   │  │   Page   │  │   Page   │  │   Page   │  │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘  │
│       │             │              │              │         │
│       └─────────────┴──────────────┴──────────────┘         │
│                          │                                   │
│                    Makes API Calls                          │
│                          │                                   │
└──────────────────────────┼───────────────────────────────────┘
                           │
                           ▼
        ┌──────────────────────────────────────┐
        │   MSW (Mock Service Worker)          │
        │   Intercepts HTTP Requests           │
        │                                      │
        │   fetch('/api/patients')             │
        │         ↓                            │
        │   Returns Mock Data                  │
        │   [{ id: 1, name: 'Alice' }]        │
        └──────────────────────────────────────┘
                           │
                           ▼
        ┌──────────────────────────────────────┐
        │   Integration Test                   │
        │                                      │
        │   1. Render component                │
        │   2. Simulate user actions           │
        │   3. Verify results                  │
        └──────────────────────────────────────┘
```

## 📁 File Structure Explained

```
src/__tests__/in