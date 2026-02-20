import { renderHook, act } from '@testing-library/react'
import { CartProvider, useCart } from './CartContext';
import { Product } from '../types';
import { expect, it } from 'vitest';

const wrapper = ({ children }: any) => <CartProvider>{children}</CartProvider>;

describe('CartContext logic', () => {
  it('adds and updates quantities correctly', () => {
    const product: Product = {
      id: '1',
      name: 'Widget',
      description: 'Test widget',
      category: 'Test',
      price: 5,
      image: '',
      rating: 0,
      reviews: 0,
      inStock: true,
    };

    const { result } = renderHook(() => useCart(), { wrapper });

    act(() => {
      result.current.addToCart(product);
    });
    expect(result.current.getTotalItems()).toBe(1);

    act(() => {
      result.current.addToCart(product, 2);
    });
    expect(result.current.getTotalItems()).toBe(3);
  });
});
