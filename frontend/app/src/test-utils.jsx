import React from 'react';
import { render } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { AuthContext } from './contexts/AuthContext';
import { ThemeProvider } from './contexts/ThemeContext';

// Default mock auth state
const defaultAuthValue = {
   user: { id: '1', name: 'Test User', email: 'test@example.com' },
   session: { access_token: 'fake-token' },
   loading: false,
   error: null,
   login: jest.fn(),
   signup: jest.fn(),
   logout: jest.fn(),
   isAuthenticated: true,
};

const AllTheProviders = ({ children, authValue }) => {
   return (
      <ThemeProvider>
         <AuthContext.Provider value={{ ...defaultAuthValue, ...authValue }}>
            <MemoryRouter>
               {children}
            </MemoryRouter>
         </AuthContext.Provider>
      </ThemeProvider>
   );
};

const customRender = (ui, options = {}) => {
   const { authValue, ...renderOptions } = options;
   return render(ui, {
      wrapper: (props) => <AllTheProviders {...props} authValue={authValue} />,
      ...renderOptions,
   });
};

// re-export everything
export * from '@testing-library/react';

// override render method
export { customRender as render };
