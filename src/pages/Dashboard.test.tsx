import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import { describe, it, expect, vi } from 'vitest';
import Dashboard from './Dashboard';
import { ordersAPI } from '../services/api';

import { within } from '@testing-library/react';

const mockNavigate = vi.fn();
vi.mock('react-router-dom', () => ({
  useNavigate: () => mockNavigate,
}));

vi.mock('../context/AuthContext', () => ({
  useAuth: () => ({
    user: { username: 'alpha' },
  }),
}));

vi.mock('../context/CartContext', () => ({
  useCart: () => ({
    getTotalItems: () => 3,
  }),
}));

vi.mock('../context/WishlistContext', () => ({
  useWishlist: () => ({
    wishlist: [{ id: 1 }, { id: 2 }],
  }),
}));

vi.mock('../services/api', () => ({
  ordersAPI: {
    getAll: vi.fn(),
  },
}));

const mockedOrders = [
  {
    _id: 'order12345678',
    createdAt: '2024-01-01',
    status: 'delivered',
    total: 50,
    items: [{ quantity: 2 }, { quantity: 1 }],
  },
  {
    _id: 'order87654321',
    createdAt: '2024-01-02',
    status: 'shipped',
    total: 30,
    items: [{ quantity: 1 }],
  },
];


describe('Dashboard', () => {
  it('renders stats and recent orders', async () => {
    (ordersAPI.getAll as any).mockResolvedValue(mockedOrders);

    render(<Dashboard />);

    expect(screen.getByText(/welcome back, alpha/i)).toBeInTheDocument();

    expect(screen.getByText('3')).toBeInTheDocument();
    expect(screen.getByText(/wishlist items/i)).toBeInTheDocument();

    await waitFor(() => {
      expect(ordersAPI.getAll).toHaveBeenCalled();
    });

    const totalOrdersCard = screen.getByText(/total orders/i).closest('div')!;
    expect(within(totalOrdersCard).getByText('2')).toBeInTheDocument();

    const orderItemsCard = screen.getByText(/order items/i).closest('div')!;
    expect(within(orderItemsCard).getByText('4')).toBeInTheDocument();
  });

  it('navigates when quick action clicked', async () => {
    (ordersAPI.getAll as any).mockResolvedValue([]);

    render(<Dashboard />);

    const cartBtn = screen.getByText(/view cart/i);
    fireEvent.click(cartBtn);

    expect(mockNavigate).toHaveBeenCalledWith('/cart');
  });

  it('shows empty state when no orders', async () => {
    (ordersAPI.getAll as any).mockResolvedValue([]);

    render(<Dashboard />);

    await waitFor(() => {
      expect(ordersAPI.getAll).toHaveBeenCalled();
    });

    expect(screen.getByText(/no orders yet/i)).toBeInTheDocument();
    expect(screen.getByText(/start shopping/i)).toBeInTheDocument();
  });
});