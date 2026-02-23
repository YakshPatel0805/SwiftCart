import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import ProductCard from './ProductCard';
import { Product } from '../../types';

const mockAddToCart = vi.fn();
const mockAddToWishlist = vi.fn();
const mockRemoveFromWishlist = vi.fn();
const mockIsInWishlist = vi.fn();
const mockUseAuth = vi.fn();

vi.mock('../../context/CartContext', () => ({
  useCart: () => ({
    addToCart: mockAddToCart,
  }),
}));

vi.mock('../../context/WishlistContext', () => ({
  useWishlist: () => ({
    addToWishlist: mockAddToWishlist,
    removeFromWishlist: mockRemoveFromWishlist,
    isInWishlist: mockIsInWishlist,
  }),
}));

vi.mock('../../context/AuthContext', () => ({
  useAuth: () => mockUseAuth(),
}));


const mockProduct: Product = {
  id: '1',
  name: 'Test Product',
  description: 'Test description',
  category: 'Test Category',
  price: 99.99,
  image: 'test.jpg',
  rating: 4,
  reviews: 120,
  inStock: true,
};


describe('ProductCard', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders product details', () => {
    mockIsInWishlist.mockReturnValue(false);
    mockUseAuth.mockReturnValue({ user: { id: '123' } });

    render(<ProductCard product={mockProduct} />);

    expect(screen.getByText('Test Product')).toBeInTheDocument();
    expect(screen.getByText('Test description')).toBeInTheDocument();
    expect(screen.getByText('$99.99')).toBeInTheDocument();
    expect(screen.getByText('(120 reviews)')).toBeInTheDocument();
  });

  it('calls addToCart when Add to Cart is clicked', () => {
    mockIsInWishlist.mockReturnValue(false);
    mockUseAuth.mockReturnValue({ user: { id: '123' } });

    render(<ProductCard product={mockProduct} />);

    fireEvent.click(screen.getByText(/add to cart/i));

    expect(mockAddToCart).toHaveBeenCalledWith(mockProduct);
  });

  it('shows Out of Stock when product is not in stock', () => {
    mockIsInWishlist.mockReturnValue(false);
    mockUseAuth.mockReturnValue({ user: { id: '123' } });

    render(
      <ProductCard
        product={{ ...mockProduct, inStock: false }}
      />
    );

    expect(screen.getByText(/out of stock/i)).toBeInTheDocument();
  });

  it('alerts if user is not logged in when clicking wishlist', () => {
    mockIsInWishlist.mockReturnValue(false);
    mockUseAuth.mockReturnValue({ user: null });

    const alertSpy = vi.spyOn(window, 'alert').mockImplementation(() => {});

    render(<ProductCard product={mockProduct} />);

    const wishlistBtn = screen.getByTitle(/add to wishlist/i);
    fireEvent.click(wishlistBtn);

    expect(alertSpy).toHaveBeenCalledWith(
      'Please login to add items to wishlist'
    );
  });

  it('adds to wishlist when not in wishlist', () => {
    mockIsInWishlist.mockReturnValue(false);
    mockUseAuth.mockReturnValue({ user: { id: '123' } });

    render(<ProductCard product={mockProduct} />);

    const wishlistBtn = screen.getByTitle(/add to wishlist/i);
    fireEvent.click(wishlistBtn);

    expect(mockAddToWishlist).toHaveBeenCalledWith(mockProduct);
  });

  it('removes from wishlist when already in wishlist', () => {
    mockIsInWishlist.mockReturnValue(true);
    mockUseAuth.mockReturnValue({ user: { id: '123' } });

    render(<ProductCard product={mockProduct} />);

    const wishlistBtn = screen.getByTitle(/remove from wishlist/i);
    fireEvent.click(wishlistBtn);

    expect(mockRemoveFromWishlist).toHaveBeenCalledWith('1');
  });

  it('renders correct number of filled stars based on rating', () => {
    mockIsInWishlist.mockReturnValue(false);
    mockUseAuth.mockReturnValue({ user: { id: '123' } });

    render(<ProductCard product={mockProduct} />);

    const stars = screen.getAllByTestId('star');
    expect(stars.length).toBe(5);
  });
});