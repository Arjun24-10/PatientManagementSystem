import * as authService from './supabaseAuth';

describe('supabaseAuth Service', () => {
   beforeEach(() => {
      jest.resetAllMocks();
      global.fetch = jest.fn();
   });

   test('signIn calls login and returns formatted result', async () => {
      const mockUser = { id: 1, email: 'test@example.com' };
      const mockResponse = { user: mockUser, token: '123' };

      global.fetch.mockResolvedValueOnce({
         ok: true,
         json: async () => mockResponse,
      });

      const result = await authService.signIn('test@example.com', 'password');

      expect(global.fetch).toHaveBeenCalledWith(
         expect.stringContaining('/auth/login'),
         expect.objectContaining({
            method: 'POST',
            body: JSON.stringify({ email: 'test@example.com', password: 'password' }),
         })
      );

      expect(result).toEqual({
         success: true,
         user: mockUser,
         session: mockResponse,
      });
   });

   test('signIn handles error', async () => {
      global.fetch.mockResolvedValueOnce({
         ok: false,
         json: async () => ({ message: 'Invalid credentials' }),
      });

      const result = await authService.signIn('test@example.com', 'wrong');

      expect(result).toEqual({
         success: false,
         error: 'Invalid credentials',
      });
   });

   test('signOut calls logout', async () => {
      global.fetch.mockResolvedValueOnce({
         ok: true,
         json: async () => ({ message: 'Logged out' }),
      });

      const result = await authService.signOut();

      expect(global.fetch).toHaveBeenCalledWith(
         expect.stringContaining('/auth/logout'),
         expect.objectContaining({ method: 'POST' })
      );

      expect(result).toEqual({ success: true });
   });
});
