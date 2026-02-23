import React from 'react';
import { describe, it, expect, beforeEach, vi } from 'vitest';
import { renderHook, act } from '@testing-library/react';
import { CartProvider, useCart } from '../context/CartContext';
import { Product } from '../types';

const wrapper = ({ children }: { children: React.ReactNode }) => (
  <CartProvider>{children}</CartProvider>
);

const mockProduct: Product = {
  id: '1',
  name: 'Test Product',
  price: 100,
  description: 'Test desc',
  image: 'test.jpg',
  category: 'test',
  rating: 4,
  reviews: 10,
  inStock: true,
};

describe('CartContext (Vitest)', () => {
  beforeEach(() => {
    localStorage.clear();
    vi.restoreAllMocks();
  });

  it('addToCart adds a new product', () => {
    const { result } = renderHook(() => useCart(), { wrapper });

    act(() => {
      result.current.addToCart(mockProduct);
    });

    expect(result.current.items.length).toBe(1);
    expect(result.current.items[0].quantity).toBe(1);
  });

  it('addToCart increases quantity if product already exists', () => {
    const { result } = renderHook(() => useCart(), { wrapper });

    act(() => {
      result.current.addToCart(mockProduct);
      result.current.addToCart(mockProduct);
    });

    expect(result.current.items[0].quantity).toBe(2);
  });

  it('removeFromCart removes product', () => {
    const { result } = renderHook(() => useCart(), { wrapper });

    act(() => {
      result.current.addToCart(mockProduct);
      result.current.removeFromCart('1');
    });

    expect(result.current.items.length).toBe(0);
  });

  it('updateQuantity updates item quantity', () => {
    const { result } = renderHook(() => useCart(), { wrapper });

    act(() => {
      result.current.addToCart(mockProduct);
      result.current.updateQuantity('1', 5);
    });

    expect(result.current.items[0].quantity).toBe(5);
  });

  it('updateQuantity removes item when quantity <= 0', () => {
    const { result } = renderHook(() => useCart(), { wrapper });

    act(() => {
      result.current.addToCart(mockProduct);
      result.current.updateQuantity('1', 0);
    });

    expect(result.current.items.length).toBe(0);
  });

  it('clearCart empties the cart', () => {
    const { result } = renderHook(() => useCart(), { wrapper });

    act(() => {
      result.current.addToCart(mockProduct);
      result.current.clearCart();
    });

    expect(result.current.items.length).toBe(0);
  });

  it('getTotalItems returns correct total quantity', () => {
    const { result } = renderHook(() => useCart(), { wrapper });

    act(() => {
      result.current.addToCart(mockProduct, 2);
      result.current.addToCart({ ...mockProduct, id: '2' }, 3);
    });

    expect(result.current.getTotalItems()).toBe(5);
  });

  it('getTotalPrice returns correct total price', () => {
    const { result } = renderHook(() => useCart(), { wrapper });

    act(() => {
      result.current.addToCart(mockProduct, 2); // 200
      result.current.addToCart({ ...mockProduct, id: '2', price: 50 }, 3); // 150
    });

    expect(result.current.getTotalPrice()).toBe(350);
  });

  it('loads cart from localStorage on init', () => {
    const storedCart = JSON.stringify([
      { product: mockProduct, quantity: 2 },
    ]);

    localStorage.setItem('cart', storedCart);

    const { result } = renderHook(() => useCart(), { wrapper });

    expect(result.current.items.length).toBe(1);
    expect(result.current.items[0].quantity).toBe(2);
  });

  it('saves cart to localStorage when items change', () => {
    const { result } = renderHook(() => useCart(), { wrapper });

    act(() => {
      result.current.addToCart(mockProduct);
    });

    const saved = JSON.parse(localStorage.getItem('cart') || '[]');
    expect(saved.length).toBe(1);
    expect(saved[0].quantity).toBe(1);
  });
});