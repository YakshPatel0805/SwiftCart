import { render, screen, fireEvent } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import Wishlist from './Wishlist';
import { vi } from 'vitest';

const mockNavigate = vi.fn();
const mockRemoveFromWishlist = vi.fn();
const mockAddToCart = vi.fn();

vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual<any>('react-router-dom');
  return {
    ...actual,
    useNavigate: () => mockNavigate,
  };
});

vi.mock('../context/WishlistContext', () => ({
  useWishlist: vi.fn(),
}));

vi.mock('../context/CartContext', () => ({
  useCart: () => ({
    addToCart: mockAddToCart,
  }),
}));

vi.mock('../context/AuthContext', () => ({
  useAuth: vi.fn(),
}));

import { useWishlist } from '../context/WishlistContext';
import { useAuth } from '../context/AuthContext';

describe('Wishlist Page', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  test('shows sign in message when user is not logged in', () => {
    (useAuth as any).mockReturnValue({ user: null });
    (useWishlist as any).mockReturnValue({
      wishlist: [],
      removeFromWishlist: mockRemoveFromWishlist,
      isLoading: false,
    });

    render(
      <MemoryRouter>
        <Wishlist />
      </MemoryRouter>
    );

    // target heading only (not button)
    expect(
      screen.getByRole('heading', { name: /please sign in to view your wishlist/i })
    ).toBeInTheDocument();

    // target button by role
    expect(
      screen.getByRole('button', { name: /^sign in$/i })
    ).toBeInTheDocument();
  });

  test('shows empty wishlist message when wishlist is empty', () => {
    (useAuth as any).mockReturnValue({ user: { id: '1', name: 'John' } });
    (useWishlist as any).mockReturnValue({
      wishlist: [],
      removeFromWishlist: mockRemoveFromWishlist,
      isLoading: false,
    });

    render(
      <MemoryRouter>
        <Wishlist />
      </MemoryRouter>
    );

    expect(
      screen.getByText(/your wishlist is empty/i)
    ).toBeInTheDocument();
  });

  test('renders wishlist items', () => {
    (useAuth as any).mockReturnValue({ user: { id: '1', name: 'John' } });
    (useWishlist as any).mockReturnValue({
      wishlist: [
        {
          id: '1',
          name: 'Product 1',
          price: 10,
          image: 'test.jpg',
          rating: 4,
          description: 'Nice product',
        },
      ],
      removeFromWishlist: mockRemoveFromWishlist,
      isLoading: false,
    });

    render(
      <MemoryRouter>
        <Wishlist />
      </MemoryRouter>
    );

    expect(screen.getByText('Product 1')).toBeInTheDocument();
    expect(screen.getByText('$10.00')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /add to cart/i })).toBeInTheDocument();
  });

  test('removes item from wishlist', async () => {
    (useAuth as any).mockReturnValue({ user: { id: '1' } });
    (useWishlist as any).mockReturnValue({
      wishlist: [
        { id: '1', name: 'Product 1', price: 10, image: 'test.jpg' },
      ],
      removeFromWishlist: mockRemoveFromWishlist,
      isLoading: false,
    });

    render(
      <MemoryRouter>
        <Wishlist />
      </MemoryRouter>
    );

    const removeButton = screen.getByTitle(/remove from wishlist/i);
    fireEvent.click(removeButton);

    expect(mockRemoveFromWishlist).toHaveBeenCalledWith('1');
  });
});