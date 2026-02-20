import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import Orders from './Orders';
import { ordersAPI } from '../services/api';

// mock navigate
const mockNavigate = vi.fn();

vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual<any>('react-router-dom');
  return {
    ...actual,
    useNavigate: () => mockNavigate,
  };
});

// mock API
vi.mock('../services/api', () => ({
  ordersAPI: {
    getAll: vi.fn(),
    cancel: vi.fn(),
  },
}));

const mockOrders = [
  {
    _id: 'order1',
    createdAt: new Date().toISOString(),
    status: 'processing',
    total: 100,
    items: [
      {
        quantity: 2,
        product: {
          name: 'Product 1',
          price: 50,
          image: 'img.jpg',
        },
      },
    ],
    shippingAddress: {
      name: 'John Doe',
      address: 'Street 1',
      city: 'Delhi',
    },
  },
];

describe('Orders Page', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('shows loading initially', () => {
    (ordersAPI.getAll as any).mockResolvedValue([]);

    render(<Orders />);

    expect(screen.getByText(/loading orders/i)).toBeInTheDocument();
  });

  it('renders orders after loading', async () => {
    (ordersAPI.getAll as any).mockResolvedValue(mockOrders);

    render(<Orders />);

    expect(await screen.findByText(/my orders/i)).toBeInTheDocument();
    expect(await screen.findByText(/order id: order1/i)).toBeInTheDocument();
    expect(await screen.findByText(/product 1/i)).toBeInTheDocument();
    const priceElements = await screen.findAllByText('$100.00');
    expect(priceElements.length).toBeGreaterThan(0);
  });

  it('opens dropdown and cancels order', async () => {
    (ordersAPI.getAll as any).mockResolvedValue(mockOrders);
    (ordersAPI.cancel as any).mockResolvedValue({});

    // mock confirm & alert
    vi.spyOn(window, 'confirm').mockReturnValue(true);
    vi.spyOn(window, 'alert').mockImplementation(() => {});

    render(<Orders />);

    // wait for order
    await screen.findByText(/order id: order1/i);

    // open dropdown (three dots)
    const menuButton = screen.getByRole('button');
    fireEvent.click(menuButton);

    // click cancel
    const cancelBtn = await screen.findByText(/cancel order/i);
    fireEvent.click(cancelBtn);

    await waitFor(() => {
      expect(ordersAPI.cancel).toHaveBeenCalledWith('order1');
    });
  });

  it('navigates when Start Shopping clicked (no orders)', async () => {
    (ordersAPI.getAll as any).mockResolvedValue([]);

    render(<Orders />);

    const btn = await screen.findByText(/start shopping/i);
    fireEvent.click(btn);

    expect(mockNavigate).toHaveBeenCalledWith('/');
  });
});