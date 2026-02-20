import { render, screen, within } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import Profile from './Profile';

// mock ChangePassword component
vi.mock('./Auth/ChangePassword', () => ({
  default: () => <div data-testid="change-password">Change Password Component</div>,
}));

// mock AuthContext
const mockUseAuth = vi.fn();

vi.mock('../context/AuthContext', () => ({
  useAuth: () => mockUseAuth(),
}));

describe('Profile Page', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('shows login message when user is not logged in', () => {
    mockUseAuth.mockReturnValue({ user: null });

    render(<Profile />);

    expect(
      screen.getByText(/please log in to view your profile/i)
    ).toBeInTheDocument();
  });

  it('renders profile info for normal user', () => {
    mockUseAuth.mockReturnValue({
      user: {
        id: '123',
        username: 'john',
        email: 'john@test.com',
        role: 'user',
      },
    });

    render(<Profile />);

    expect(screen.getByRole('heading', { name: 'john' })).toBeInTheDocument();
    expect(screen.getByText('john@test.com')).toBeInTheDocument();
    
    // role badge
    const roleSection = screen.getByText(/account role/i).closest('div')!;
    expect(within(roleSection).getByText(/^user$/i)).toBeInTheDocument();

    // Change password section
    expect(screen.getByTestId('change-password')).toBeInTheDocument();
  });

it('renders admin badge and admin message for admin user', () => {
  mockUseAuth.mockReturnValue({
    user: {
      id: '999',
      username: 'admin',
      email: 'admin@test.com',
      role: 'admin',
    },
  });

  render(<Profile />);

  // username (header)
  expect(
    screen.getByRole('heading', { name: 'admin' })
  ).toBeInTheDocument();

  // role badge
  expect(
    screen.getByText(/administrator/i)
  ).toBeInTheDocument();

  // admin message
  expect(
    screen.getByText(/administrative privileges/i)
  ).toBeInTheDocument();
});
});