import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import ChangePassword from './ChangePassword';
import { authAPI } from '../../services/api';


vi.mock('../../services/api', () => ({
  authAPI: {
    changePassword: vi.fn(),
  },
}));

describe('ChangePassword Component', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  const fillForm = () => {
    fireEvent.change(screen.getByPlaceholderText(/enter your email address/i), {
      target: { value: 'test@example.com' },
    });

    fireEvent.change(screen.getByPlaceholderText(/enter your current password/i), {
      target: { value: 'oldpass123' },
    });

    fireEvent.change(screen.getByPlaceholderText(/enter new password/i), {
      target: { value: 'newpass123' },
    });

    fireEvent.change(screen.getByPlaceholderText(/confirm new password/i), {
      target: { value: 'newpass123' },
    });
  };


  it('updates input values when typing', () => {
    render(<ChangePassword />);

    const emailInput = screen.getByPlaceholderText(/enter your email address/i);
    fireEvent.change(emailInput, { target: { value: 'user@test.com' } });

    expect(emailInput).toHaveValue('user@test.com');
  });


  it('toggles old password visibility', () => {
    render(<ChangePassword />);

    const passwordInput = screen.getByPlaceholderText(/enter your current password/i);
    const toggleBtn = passwordInput.nextSibling as HTMLElement;

    expect(passwordInput).toHaveAttribute('type', 'password');

    fireEvent.click(toggleBtn);
    expect(passwordInput).toHaveAttribute('type', 'text');
  });


 it('shows error if fields are empty', async () => {
  const { container } = render(<ChangePassword />);

  const form = container.querySelector('form')!;
  fireEvent.submit(form);

  await waitFor(() => {
    expect(
      screen.getByText(/all fields are required/i)
    ).toBeInTheDocument();
  });
});


  it('shows error when passwords do not match', async () => {
    render(<ChangePassword />);

    fireEvent.change(screen.getByPlaceholderText(/enter your email address/i), {
      target: { value: 'test@example.com' },
    });

    fireEvent.change(screen.getByPlaceholderText(/enter your current password/i), {
      target: { value: 'oldpass123' },
    });

    fireEvent.change(screen.getByPlaceholderText(/enter new password/i), {
      target: { value: 'newpass123' },
    });

    fireEvent.change(screen.getByPlaceholderText(/confirm new password/i), {
      target: { value: 'wrongpass' },
    });

    fireEvent.click(screen.getByText(/update password/i));

    await waitFor(() => {
      expect(screen.getByText(/new passwords do not match/i)).toBeInTheDocument();
    });
  });


  it('shows error if password is too short', async () => {
    render(<ChangePassword />);

    fireEvent.change(screen.getByPlaceholderText(/enter your email address/i), {
      target: { value: 'test@example.com' },
    });

    fireEvent.change(screen.getByPlaceholderText(/enter your current password/i), {
      target: { value: 'oldpass123' },
    });

    fireEvent.change(screen.getByPlaceholderText(/enter new password/i), {
      target: { value: '123' },
    });

    fireEvent.change(screen.getByPlaceholderText(/confirm new password/i), {
      target: { value: '123' },
    });

    fireEvent.click(screen.getByText(/update password/i));

    await waitFor(() => {
      expect(
        screen.getByText(/password must be at least 6 characters/i)
      ).toBeInTheDocument();
    });
  });


  it('shows error if old and new password are same', async () => {
    render(<ChangePassword />);

    fireEvent.change(screen.getByPlaceholderText(/enter your email address/i), {
      target: { value: 'test@example.com' },
    });

    fireEvent.change(screen.getByPlaceholderText(/enter your current password/i), {
      target: { value: 'samepass' },
    });

    fireEvent.change(screen.getByPlaceholderText(/enter new password/i), {
      target: { value: 'samepass' },
    });

    fireEvent.change(screen.getByPlaceholderText(/confirm new password/i), {
      target: { value: 'samepass' },
    });

    fireEvent.click(screen.getByText(/update password/i));

    await waitFor(() => {
      expect(
        screen.getByText(/new password must be different/i)
      ).toBeInTheDocument();
    });
  });


  it('submits form successfully', async () => {
    (authAPI.changePassword as any).mockResolvedValueOnce({
      message: 'Password updated',
    });

    render(<ChangePassword />);
    fillForm();

    fireEvent.click(screen.getByText(/update password/i));

    await waitFor(() => {
      expect(
        screen.getByText(/password changed successfully/i)
      ).toBeInTheDocument();
    });

    expect(authAPI.changePassword).toHaveBeenCalledWith(
      'test@example.com',
      'oldpass123',
      'newpass123',
      'newpass123'
    );
  });


  it('shows error when API returns failure', async () => {
    (authAPI.changePassword as any).mockResolvedValueOnce({
      message: 'error: invalid password',
    });

    render(<ChangePassword />);
    fillForm();

    fireEvent.click(screen.getByText(/update password/i));

    await waitFor(() => {
      expect(screen.getByText(/invalid password/i)).toBeInTheDocument();
    });
  });


  it('shows loading text while submitting', async () => {
    (authAPI.changePassword as any).mockResolvedValueOnce({
      message: 'Password updated',
    });

    render(<ChangePassword />);
    fillForm();

    fireEvent.click(screen.getByText(/update password/i));

    expect(screen.getByText(/updating/i)).toBeInTheDocument();
  });
});