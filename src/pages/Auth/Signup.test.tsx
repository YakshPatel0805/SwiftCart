import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import Signup from './Signup';

const mockNavigate = vi.fn();
vi.mock('react-router-dom', () => ({
  useNavigate: () => mockNavigate,
}));

const mockSignup = vi.fn();
vi.mock('../../context/AuthContext', () => ({
  useAuth: () => ({
    signup: mockSignup,
  }),
}));

describe('Signup Component', () => {
  beforeEach(() => {
    mockSignup.mockReset();
    mockNavigate.mockReset();
  });


  it('updates input values when typing', () => {
    render(<Signup />);

    const emailInput = screen.getByPlaceholderText('Enter your email');
    fireEvent.change(emailInput, { target: { value: 'test@gmail.com' } });

    expect(emailInput).toHaveValue('test@gmail.com');
  });


  it('shows error when passwords do not match', async () => {
    render(<Signup />);

    fireEvent.change(screen.getByPlaceholderText('Enter your email'), {
      target: { value: 'test@gmail.com' },
    });
    fireEvent.change(screen.getByPlaceholderText('Choose a username'), {
      target: { value: 'testuser' },
    });
    fireEvent.change(screen.getByPlaceholderText('Create a password'), {
      target: { value: '123456' },
    });
    fireEvent.change(screen.getByPlaceholderText('Confirm your password'), {
      target: { value: '12345' },
    });

    fireEvent.click(screen.getByText('Create account'));

    expect(await screen.findByText('Passwords do not match')).toBeInTheDocument();
  });


  it('shows error when password is too short', async () => {
    render(<Signup />);

    fireEvent.change(screen.getByPlaceholderText('Enter your email'), {
      target: { value: 'test@gmail.com' },
    });
    fireEvent.change(screen.getByPlaceholderText('Choose a username'), {
      target: { value: 'testuser' },
    });
    fireEvent.change(screen.getByPlaceholderText('Create a password'), {
      target: { value: '123' },
    });
    fireEvent.change(screen.getByPlaceholderText('Confirm your password'), {
      target: { value: '123' },
    });

    fireEvent.click(screen.getByText('Create account'));

    expect(
      await screen.findByText('Password must be at least 6 characters long')
    ).toBeInTheDocument();
  });

 
  it('assigns admin role if admin credentials are used', async () => {
    mockSignup.mockResolvedValue(true);

    render(<Signup />);

    fireEvent.change(screen.getByPlaceholderText('Enter your email'), {
      target: { value: 'admin@gmail.com' },
    });
    fireEvent.change(screen.getByPlaceholderText('Choose a username'), {
      target: { value: 'admin' },
    });
    fireEvent.change(screen.getByPlaceholderText('Create a password'), {
      target: { value: '123456' },
    });
    fireEvent.change(screen.getByPlaceholderText('Confirm your password'), {
      target: { value: '123456' },
    });

    fireEvent.click(screen.getByText('Create account'));

    await waitFor(() => {
      expect(mockSignup).toHaveBeenCalledWith(
        'admin@gmail.com',
        'admin',
        '123456',
        'admin'
      );
    });
  });


  it('assigns user role for normal users', async () => {
    mockSignup.mockResolvedValue(true);

    render(<Signup />);

    fireEvent.change(screen.getByPlaceholderText('Enter your email'), {
      target: { value: 'user@gmail.com' },
    });
    fireEvent.change(screen.getByPlaceholderText('Choose a username'), {
      target: { value: 'user1' },
    });
    fireEvent.change(screen.getByPlaceholderText('Create a password'), {
      target: { value: '123456' },
    });
    fireEvent.change(screen.getByPlaceholderText('Confirm your password'), {
      target: { value: '123456' },
    });

    fireEvent.click(screen.getByText('Create account'));

    await waitFor(() => {
      expect(mockSignup).toHaveBeenCalledWith(
        'user@gmail.com',
        'user1',
        '123456',
        'user'
      );
    });
  });

 
  it('navigates to login page on successful signup', async () => {
    mockSignup.mockResolvedValue(true);

    render(<Signup />);

    fireEvent.change(screen.getByPlaceholderText('Enter your email'), {
      target: { value: 'user@gmail.com' },
    });
    fireEvent.change(screen.getByPlaceholderText('Choose a username'), {
      target: { value: 'user1' },
    });
    fireEvent.change(screen.getByPlaceholderText('Create a password'), {
      target: { value: '123456' },
    });
    fireEvent.change(screen.getByPlaceholderText('Confirm your password'), {
      target: { value: '123456' },
    });

    fireEvent.click(screen.getByText('Create account'));

    await waitFor(() => {
      expect(mockNavigate).toHaveBeenCalledWith('/login');
    });
  });


  it('shows error when signup fails', async () => {
    mockSignup.mockResolvedValue(false);

    render(<Signup />);

    fireEvent.change(screen.getByPlaceholderText('Enter your email'), {
      target: { value: 'user@gmail.com' },
    });
    fireEvent.change(screen.getByPlaceholderText('Choose a username'), {
      target: { value: 'user1' },
    });
    fireEvent.change(screen.getByPlaceholderText('Create a password'), {
      target: { value: '123456' },
    });
    fireEvent.change(screen.getByPlaceholderText('Confirm your password'), {
      target: { value: '123456' },
    });

    fireEvent.click(screen.getByText('Create account'));

    expect(
      await screen.findByText('Username or email already exists')
    ).toBeInTheDocument();
  });
});