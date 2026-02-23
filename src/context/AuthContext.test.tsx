import { render, screen, waitFor } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { AuthProvider, useAuth } from './AuthContext';

vi.mock('../services/api', () => ({
  authAPI: {
    login: vi.fn(),
    signup: vi.fn(),
  },
}));

import { authAPI } from '../services/api';

function TestComponent() {
  const { user, login, signup, logout, isLoading } = useAuth();

  return (
    <div>
      <div data-testid="loading">{isLoading ? 'loading' : 'loaded'}</div>
      <div data-testid="user">{user ? user.email : 'no-user'}</div>

      <button onClick={() => login('test@gmail.com', '123456')}>
        login
      </button>

      <button onClick={() =>
        signup('new@gmail.com', 'newuser', '123456', 'user')
      }>
        signup
      </button>

      <button onClick={logout}>logout</button>
    </div>
  );
}

describe('AuthContext', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    localStorage.clear();
  });


  it('loads user from localStorage on mount', async () => {
    localStorage.setItem(
      'user',
      JSON.stringify({
        id: 1,
        email: 'saved@gmail.com',
        username: 'saved',
        role: 'user',
      })
    );
    localStorage.setItem('token', 'abc123');

    render(
      <AuthProvider>
        <TestComponent />
      </AuthProvider>
    );

    await waitFor(() => {
      expect(screen.getByTestId('user').textContent).toBe('saved@gmail.com');
    });
  });


  it('login sets user and token when successful', async () => {
    (authAPI.login as any).mockResolvedValue({
      token: 'token123',
      user: {
        id: 1,
        email: 'test@gmail.com',
        username: 'test',
        role: 'admin',
      },
    });

    render(
      <AuthProvider>
        <TestComponent />
      </AuthProvider>
    );

    screen.getByText('login').click();

    await waitFor(() => {
      expect(localStorage.getItem('token')).toBe('token123');
      expect(JSON.parse(localStorage.getItem('user')!)).toMatchObject({
        email: 'test@gmail.com',
        role: 'admin',
      });
    });
  });


  it('login returns false if API fails', async () => {
    (authAPI.login as any).mockRejectedValue(new Error('fail'));

    render(
      <AuthProvider>
        <TestComponent />
      </AuthProvider>
    );

    screen.getByText('login').click();

    await waitFor(() => {
      expect(localStorage.getItem('user')).toBeNull();
    });
  });


  it('signup sets user and token when successful', async () => {
    (authAPI.signup as any).mockResolvedValue({
      token: 'signup-token',
      user: {
        id: 2,
        email: 'new@gmail.com',
        username: 'newuser',
        role: 'user',
      },
    });

    render(
      <AuthProvider>
        <TestComponent />
      </AuthProvider>
    );

    screen.getByText('signup').click();

    await waitFor(() => {
      expect(localStorage.getItem('token')).toBe('signup-token');
      expect(JSON.parse(localStorage.getItem('user')!)).toMatchObject({
        email: 'new@gmail.com',
        role: 'user',
      });
    });
  });


  it('signup returns false when API throws error', async () => {
    (authAPI.signup as any).mockRejectedValue(new Error('fail'));

    render(
      <AuthProvider>
        <TestComponent />
      </AuthProvider>
    );

    screen.getByText('signup').click();

    await waitFor(() => {
      expect(localStorage.getItem('user')).toBeNull();
    });
  });


  it('logout clears user and token', async () => {
    localStorage.setItem(
      'user',
      JSON.stringify({
        id: 1,
        email: 'test@gmail.com',
        username: 'test',
        role: 'user',
      })
    );
    localStorage.setItem('token', 'token123');

    render(
      <AuthProvider>
        <TestComponent />
      </AuthProvider>
    );

    screen.getByText('logout').click();

    await waitFor(() => {
      expect(localStorage.getItem('user')).toBeNull();
      expect(localStorage.getItem('token')).toBeNull();
    });
  });
});