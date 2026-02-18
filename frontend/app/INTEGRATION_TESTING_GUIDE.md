# Integration Testing Quick Start Guide

## What I Created For You

I've set up a complete integration testing framework for your frontend application. Here's what's been added:

### 📁 File Structure Created

```
frontend/app/src/__tests__/integration/
├── setup/
│   ├── msw-handlers.js          ✅ Mock API responses
│   ├── test-server.js           ✅ Mock server setup
│   └── integration-utils.jsx    ✅ Test helper functions
├── auth-flow.test.jsx           ✅ Login/logout tests
├── doctor-workflow.test.jsx     ✅ Doctor journey tests
├── patient-workflow.test.jsx    ✅ Patient journey tests
├── nurse-workflow.test.jsx      ✅ Nurse workflow tests
├── lab-workflow.test.jsx        ✅ Lab tech workflow tests
├── admin-workflow.test.jsx      ✅ Admin workflow tests
└── README.md                    ✅ Detailed documentation
```

## 🎯 What Are Integration Tests?

**Unit Tests** test individual components in isolation:
```javascript
// Unit test - tests one component alone
test('Button renders correctly', () => {
  render(<Button />);
  expect(screen.getByRole('button')).toBeInTheDocument();
});
```

**Integration Tests** test complete user workflows:
```javascript
// Integration test - tests multiple components working together
test('User can login and view dashboard', async () => {
  // 1. User visits login page
  render(<App />);
  
  // 2. User enters credentials
  await user.type(screen.getByLabelText(/email/i), 'doctor@test.com');
  await user.type(screen.getByLabelText(/password/i), 'password123');
  
  // 3. User clicks login
  await user.click(screen.getByRole('button', { name: /sign in/i }));
  
  // 4. User sees dashboard
  await waitFor(() => {
    expect(screen.getByText(/dashboard/i)).toBeInTheDocument();
  });
});
```

## 🚀 Getting Started

### Step 1: Install Dependencies

```bash
cd frontend/app
npm install
```

This will install MSW (Mock Service Worker) which I added to your package.json.

### Step 2: Run Integration Tests

```bash
# Run all integration tests
npm run test:integration

# Run only unit tests (excludes integration)
npm run test:unit

# Run all tests
npm test
```

### Step 3: Run Specific Test Files

```bash
# Test authentication flow
npm test -- auth-flow.test.jsx

# Test doctor workflow
npm test -- doctor-workflow.test.jsx

# Test patient workflow
npm test -- patient-workflow.test.jsx
```

## 📚 How It Works

### 1. Mock Service Worker (MSW)

MSW intercepts HTTP requests at the network level and returns mock data:

```javascript
// Your component makes a real fetch call
fetch('http://localhost:8080/api/patients')

// MSW intercepts it and returns mock data
// No real backend needed!
```

**Benefits:**
- Tests use real fetch calls (not mocked functions)
- Tests are closer to production behavior
- Easy to add/modify mock responses
- No need for running backend during tests

### 2. Test Structure

Each test file follows this pattern:

```javascript
// 1. Setup mock server
setupTestServer();

// 2. Write tests
describe('User Workflow', () => {
  test('should complete action', async () => {
    // 3. Render component with providers
    renderWithProviders(<Component />, {
      authValue: mockAuthUsers.doctor,
    });
    
    // 4. Simulate user actions
    const user = userEvent.setup();
    await user.click(screen.getByRole('button'));
    
    // 5. Verify results
    await waitFor(() => {
      expect(screen.getByText(/success/i)).toBeInTheDocument();
    });
  });
});
```

### 3. Mock Data

All mock data is centralized in `msw-handlers.js`:

```javascript
export const mockPatients = [
  { id: '101', name: 'Alice Johnson', age: 45 },
  { id: '102', name: 'Bob Williams', age: 62 },
];
```

**To add more mock data:**
1. Open `frontend/app/src/__tests__/integration/setup/msw-handlers.js`
2. Add your mock data to the exports
3. Add corresponding API handlers

## 🔧 Customizing Tests

### Adding New API Endpoints

Edit `msw-handlers.js`:

```javascript
export const handlers = [
  // Add new endpoint
  http.get('http://localhost:8080/api/your-endpoint', () => {
    return HttpResponse.json({ data: 'your mock data' });
  }),
];
```

### Adding New Test Cases

Create a new test in any workflow file:

```javascript
test('should do something specific', async () => {
  const user = userEvent.setup();
  
  renderWithProviders(<YourComponent />, {
    authValue: mockAuthUsers.doctor,
  });
  
  // Your test logic here
});
```

### Testing Different User Roles

Use the pre-configured mock users:

```javascript
// Test as doctor
renderWithProviders(<Component />, {
  authValue: mockAuthUsers.doctor,
});

// Test as patient
renderWithProviders(<Component />, {
  authValue: mockAuthUsers.patient,
});

// Test as unauthenticated user
renderWithProviders(<Component />, {
  authValue: mockAuthUsers.unauthenticated,
});
```

## 📝 Test Coverage

### What's Tested

✅ **Authentication Flow**
- Login with valid/invalid credentials
- Form validation
- Password visibility
- Remember me functionality

✅ **Doctor Workflow**
- View patient list
- Search/filter patients
- View patient details
- Manage appointments
- Handle API errors

✅ **Patient Workflow**
- View dashboard
- Book appointments
- View lab results
- Access medical history
- View prescriptions

✅ **Nurse Workflow**
- Record vital signs
- View vitals history
- Update patient vitals
- Validate input

✅ **Lab Workflow**
- View pending orders
- Process orders
- Upload results
- View history

✅ **Admin Workflow**
- View system dashboard
- Manage users
- View reports
- System settings

### What Needs Your Attention

Some tests are placeholders because they depend on your specific component implementation:

```javascript
// Placeholder test - needs your component details
test('should search patients', async () => {
  const searchInput = screen.queryByPlaceholderText(/search/i);
  if (searchInput) {
    // Test logic here
  }
});
```

**To complete these:**
1. Look for tests with `if (element)` checks
2. Update based on your actual component structure
3. Add assertions for your specific UI elements

## 🐛 Troubleshooting

### "Cannot find module 'msw'"
```bash
npm install --save-dev msw
```

### Tests timeout
- Check if you're waiting for elements that don't exist
- Increase timeout: `test('name', async () => {...}, 10000)`

### Mock server not working
- Ensure `setupTestServer()` is called at the top of test file
- Check API URLs match between handlers and your code
- Verify handler syntax is correct

### Tests fail randomly
- Tests may not be isolated
- Check for shared state between tests
- Ensure proper cleanup in `afterEach`

## 📖 Example: Complete Test Walkthrough

Let's walk through a complete integration test:

```javascript
test('doctor can view and schedule appointment', async () => {
  // 1. Setup user interaction helper
  const user = userEvent.setup();
  
  // 2. Render appointments page as authenticated doctor
  renderWithProviders(<DoctorAppointments />, {
    authValue: mockAuthUsers.doctor,
    initialRoute: '/dashboard/doctor/appointments',
  });
  
  // 3. Wait for appointments to load from mock API
  await waitFor(() => {
    expect(screen.getByText(/alice johnson/i)).toBeInTheDocument();
  });
  
  // 4. User clicks "New Appointment" button
  const newButton = screen.getByRole('button', { name: /new appointment/i });
  await user.click(newButton);
  
  // 5. User fills in appointment form
  await user.type(screen.getByLabelText(/patient/i), 'Alice Johnson');
  await user.type(screen.getByLabelText(/date/i), '2024-02-15');
  await user.type(screen.getByLabelText(/time/i), '10:00 AM');
  
  // 6. User submits form
  await user.click(screen.getByRole('button', { name: /schedule/i }));
  
  // 7. Verify success message appears
  await waitFor(() => {
    expect(screen.getByText(/appointment scheduled/i)).toBeInTheDocument();
  });
  
  // 8. Verify new appointment appears in list
  expect(screen.getByText(/2024-02-15/i)).toBeInTheDocument();
});
```

**This test verifies:**
- Component renders correctly
- API data loads
- User can interact with UI
- Form submission works
- Success feedback is shown
- Data updates in the UI

## 🎓 Best Practices

### ✅ DO:
- Test user workflows, not implementation
- Use realistic mock data
- Test both success and error scenarios
- Wait for async operations with `waitFor`
- Use descriptive test names
- Keep tests independent

### ❌ DON'T:
- Test internal component state
- Use arbitrary timeouts (`setTimeout`)
- Make tests depend on each other
- Mock everything (use MSW for APIs)
- Test styling or CSS
- Duplicate unit test coverage

## 🔄 Next Steps

1. **Install dependencies**: `npm install`
2. **Run tests**: `npm run test:integration`
3. **Review test output** and see what passes/fails
4. **Update placeholder tests** based on your components
5. **Add more test cases** for your specific features
6. **Update mock data** to match your API responses
7. **Run tests in CI/CD** pipeline

## 📚 Additional Resources

- [Full README](./src/__tests__/integration/README.md) - Detailed documentation
- [React Testing Library](https://testing-library.com/docs/react-testing-library/intro/)
- [MSW Documentation](https://mswjs.io/docs/)
- [Testing Best Practices](https://kentcdodds.com/blog/common-mistakes-with-react-testing-library)

## 💡 Key Takeaways

1. **Integration tests verify workflows**, not individual components
2. **MSW mocks APIs at the network level**, making tests realistic
3. **Tests are organized by user role** (doctor, patient, nurse, etc.)
4. **Mock data is centralized** for easy maintenance
5. **Tests simulate real user interactions** (click, type, wait)
6. **Some tests need your input** to match your specific components

---

**Questions?** Check the detailed README in `src/__tests__/integration/README.md` or review the test files for examples!
