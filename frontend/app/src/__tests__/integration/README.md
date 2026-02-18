# Integration Tests

This directory contains integration tests for the Patient Management System frontend. Integration tests verify that multiple components work together correctly, testing complete user workflows rather than isolated components.

## What Are Integration Tests?

Unlike unit tests that test individual components in isolation, integration tests:
- Test complete user journeys (e.g., login → view patients → schedule appointment)
- Verify multiple components work together correctly
- Test real data flow through the application
- Mock API calls at the network level (not individual functions)
- Ensure navigation and routing work properly

## Directory Structure

```
__tests__/integration/
├── setup/
│   ├── msw-handlers.js          # Mock API responses
│   ├── test-server.js           # MSW server configuration
│   └── integration-utils.jsx    # Helper functions for tests
├── auth-flow.test.jsx           # Authentication workflow tests
├── doctor-workflow.test.jsx     # Doctor user journey tests
├── patient-workflow.test.jsx    # Patient user journey tests
├── nurse-workflow.test.jsx      # Nurse user journey tests
├── lab-workflow.test.jsx        # Lab technician workflow tests
├── admin-workflow.test.jsx      # Admin workflow tests
└── README.md                    # This file
```

## Setup Files Explained[p,]

### msw-handlers.js
- Defines how the mock server responds to API calls
- Contains mock data for users, patients, appointments, etc.
- Intercepts HTTP requests and returns fake data
- **Why?** This lets us test without a real backend running

### test-server.js
- Configures and starts/stops the mock server
- Ensures tests don't interfere with each other
- **Why?** Provides a clean slate for each test

### integration-utils.jsx
- Helper functions to render components with all providers (Auth, Router)
- Mock user data for different roles
- **Why?** Reduces code duplication across tests

## Test Files Explained

Each workflow test file tests a complete user journey:

### auth-flow.test.jsx
Tests authentication workflows:
- Login with valid/invalid credentials
- Form validation
- Password visibility toggle
- Remember me functionality
- Logout

### doctor-workflow.test.jsx
Tests doctor user journeys:
- View patient list
- Search and filter patients
- View patient details
- Schedule appointments
- Manage prescriptions
- View lab results

### patient-workflow.test.jsx
Tests patient user journeys:
- View personal dashboard
- Book appointments
- View lab results
- Access medical history
- Check prescriptions

### nurse-workflow.test.jsx
Tests nurse user journeys:
- View assigned patients
- Record vital signs
- Update patient vitals
- View vitals history

### lab-workflow.test.jsx
Tests lab technician journeys:
- View pending lab orders
- Process orders
- Upload test results
- View order history

### admin-workflow.test.jsx
Tests admin user journeys:
- View system dashboard
- Manage users
- View reports and analytics
- Update system settings

## How to Run Integration Tests

### Run all integration tests:
```bash
npm test -- __tests__/integration
```

### Run a specific workflow:
```bash
npm test -- auth-flow.test.jsx
npm test -- doctor-workflow.test.jsx
npm test -- patient-workflow.test.jsx
```

### Run in watch mode (re-runs on file changes):
```bash
npm test -- --watch __tests__/integration
```

### Run with coverage:
```bash
npm test -- --coverage __tests__/integration
```

## Installing MSW (Mock Service Worker)

Before running integration tests, you need to install MSW:

```bash
npm install --save-dev msw
```

MSW intercepts network requests and returns mock data, allowing you to test without a real backend.

## Writing New Integration Tests

### 1. Import necessary utilities:
```javascript
import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { renderWithProviders, mockAuthUsers } from './setup/integration-utils';
import { setupTestServer } from './setup/test-server';
```

### 2. Setup the mock server:
```javascript
setupTestServer();
```

### 3. Write tests that follow user workflows:
```javascript
test('should complete booking workflow', async () => {
  const user = userEvent.setup();
  
  // Render the component
  renderWithProviders(<AppointmentPage />, {
    authValue: mockAuthUsers.patient,
  });
  
  // Simulate user actions
  await user.click(screen.getByRole('button', { name: /book appointment/i }));
  await user.type(screen.getByLabelText(/date/i), '2024-02-15');
  await user.click(screen.getByRole('button', { name: /confirm/i }));
  
  // Verify the result
  await waitFor(() => {
    expect(screen.getByText(/appointment confirmed/i)).toBeInTheDocument();
  });
});
```

## Best Practices

1. **Test user workflows, not implementation details**
   - Focus on what the user sees and does
   - Don't test internal state or function calls

2. **Use realistic mock data**
   - Mock data should resemble real API responses
   - Include edge cases (empty lists, errors, etc.)

3. **Test happy paths and error scenarios**
   - Test successful workflows
   - Test what happens when APIs fail
   - Test validation errors

4. **Keep tests independent**
   - Each test should work in isolation
   - Don't rely on test execution order
   - Clean up after each test

5. **Use descriptive test names**
   - Name should describe the user action and expected result
   - Example: "should display error when login fails"

6. **Wait for async operations**
   - Always use `waitFor` for async updates
   - Don't use arbitrary timeouts

## Common Patterns

### Rendering with authentication:
```javascript
renderWithProviders(<Component />, {
  authValue: mockAuthUsers.doctor,
});
```

### Mocking API responses:
```javascript
server.use(
  http.get('http://localhost:8080/api/patients', () => {
    return HttpResponse.json([{ id: '1', name: 'Test Patient' }]);
  })
);
```

### Simulating user interactions:
```javascript
const user = userEvent.setup();
await user.type(screen.getByLabelText(/email/i), 'test@example.com');
await user.click(screen.getByRole('button', { name: /submit/i }));
```

### Waiting for elements:
```javascript
await waitFor(() => {
  expect(screen.getByText(/success/i)).toBeInTheDocument();
});
```

## Troubleshooting

### Tests fail with "Cannot find module 'msw'"
- Run: `npm install --save-dev msw`

### Tests timeout
- Increase timeout in test: `test('name', async () => {...}, 10000)`
- Check if you're waiting for elements that never appear

### Mock server not intercepting requests
- Ensure `setupTestServer()` is called
- Check API URL matches in handlers
- Verify handlers are defined correctly

### Tests pass individually but fail together
- Tests may not be isolated
- Check for shared state or side effects
- Ensure proper cleanup in afterEach

## Next Steps

1. **Install MSW**: `npm install --save-dev msw`
2. **Run tests**: `npm test -- __tests__/integration`
3. **Add more test cases** based on your specific components
4. **Update mock data** to match your actual API responses
5. **Add E2E tests** for critical user journeys

## Resources

- [React Testing Library Docs](https://testing-library.com/docs/react-testing-library/intro/)
- [MSW Documentation](https://mswjs.io/docs/)
- [Jest Documentation](https://jestjs.io/docs/getting-started)
- [Testing Best Practices](https://kentcdodds.com/blog/common-mistakes-with-react-testing-library)
