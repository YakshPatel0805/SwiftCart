import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import Login from './Login';

const mockNavigate = vi.fn();
vi.mock('react-router-dom', () => ({
  useNavigate: () => mockNavigate,
}));


const mockLogin = vi.fn();
vi.mock('../../context/AuthContext', () => ({
  useAuth: () => ({
    login: mockLogin,
  }),
}));

describe('Login Component', () => {
  beforeEach(() => {
    mockLogin.mockReset();
    mockNavigate.mockReset();
    localStorage.clear();
  });


  it('updates input values when typing', () => {
    render(<Login />);

    const emailInput = screen.getByPlaceholderText('Enter your email');
    fireEvent.change(emailInput, { target: { value: 'test@gmail.com' } });

    expect(emailInput).toHaveValue('test@gmail.com');
  });


  it('redirects admin to /admin', async () => {
    mockLogin.mockResolvedValue(true);

    localStorage.setItem(
      'user',
      JSON.stringify({ email: 'admin@gmail.com', role: 'admin' })
    );

    render(<Login />);

    fireEvent.change(screen.getByPlaceholderText('Enter your email'), {
      target: { value: 'admin@gmail.com' },
    });
    fireEvent.change(screen.getByPlaceholderText('Enter your password'), {
      target: { value: '123456' },
    });

    fireEvent.click(screen.getByText('Sign in'));

    await waitFor(() => {
      expect(mockNavigate).toHaveBeenCalledWith('/admin');
    });
  });


  it('redirects normal user to /dashboard', async () => {
    mockLogin.mockResolvedValue(true);

    localStorage.setItem(
      'user',
      JSON.stringify({ email: 'user@gmail.com', role: 'user' })
    );

    render(<Login />);

    fireEvent.change(screen.getByPlaceholderText('Enter your email'), {
      target: { value: 'user@gmail.com' },
    });
    fireEvent.change(screen.getByPlaceholderText('Enter your password'), {
      target: { value: '123456' },
    });

    fireEvent.click(screen.getByText('Sign in'));

    await waitFor(() => {
      expect(mockNavigate).toHaveBeenCalledWith('/dashboard');
    });
  });


  it('shows error when login fails', async () => {
    mockLogin.mockResolvedValue(false);

    render(<Login />);

    fireEvent.change(screen.getByPlaceholderText('Enter your email'), {
      target: { value: 'wrong@gmail.com' },
    });
    fireEvent.change(screen.getByPlaceholderText('Enter your password'), {
      target: { value: 'wrongpass' },
    });

    fireEvent.click(screen.getByText('Sign in'));

    expect(
      await screen.findByText('Invalid email or password')
    ).toBeInTheDocument();
  });


  it('shows error when login throws error', async () => {
    mockLogin.mockRejectedValue(new Error('Network error'));

    render(<Login />);

    fireEvent.change(screen.getByPlaceholderText('Enter your email'), {
      target: { value: 'test@gmail.com' },
    });
    fireEvent.change(screen.getByPlaceholderText('Enter your password'), {
      target: { value: '123456' },
    });

    fireEvent.click(screen.getByText('Sign in'));

    expect(
      await screen.findByText('An error occurred during login')
    ).toBeInTheDocument();
  });


  it('navigates to signup page when clicking create account', () => {
    render(<Login />);

    fireEvent.click(screen.getByText('create a new account'));

    expect(mockNavigate).toHaveBeenCalledWith('/signup');
  });


  it('navigates to change password page', () => {
    render(<Login />);

    fireEvent.click(screen.getByText('Forgot your password?'));

    expect(mockNavigate).toHaveBeenCalledWith('/change-password');
  });
});