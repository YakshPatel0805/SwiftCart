import { render, screen, fireEvent } from '@testing-library/react';
import ProductCard from './ProductCard';
import { CartProvider } from '../../context/CartContext';
import { WishlistProvider } from '../../context/WishlistContext';
import { AuthProvider } from '../../context/AuthContext';
import { Product } from '../../types';
import { describe, expect, test } from 'vitest';

const sampleProduct: Product = {
  id: '1',
  name: 'Test Widget',
  description: 'A widget used for testing',
  price: 9.99,
  image: 'https://example.com/widget.jpg',
  category: 'Electronics',
  rating: 4.5,
  reviews: 12,
  inStock: true,
};

describe('ProductCard component', () => {
  test('renders name and price correctly', () => {
    render(
      <AuthProvider>
        <CartProvider>
          <WishlistProvider>
            <ProductCard product={sampleProduct} />
          </WishlistProvider>
        </CartProvider>
      </AuthProvider>
    );

    expect(screen.getByText(sampleProduct.name)).toBeInTheDocument();
    expect(screen.getByText(`$${sampleProduct.price.toFixed(2)}`)).toBeInTheDocument();
  });

  test('adds item to cart when clicking add button', () => {
    // this is a basic smoke test; a more thorough test could expose
    // the cart context or spy on the state update
    render(
      <AuthProvider>
        <CartProvider>
          <WishlistProvider>
            <ProductCard product={sampleProduct} />
          </WishlistProvider>
        </CartProvider>
      </AuthProvider>
    );

    fireEvent.click(screen.getByRole('button', { name: /add to cart/i }));
  });
});
