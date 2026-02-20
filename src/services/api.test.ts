import { describe, it, expect, beforeEach, vi } from 'vitest';
import {
  authAPI,
  productsAPI,
  ordersAPI,
  wishlistAPI,
  contactAPI
} from './api';

const API_BASE_URL = process.env.API_BASE_URL || 'http://localhost:5000/api';

global.fetch = vi.fn();

const mockFetch = fetch as unknown as ReturnType<typeof vi.fn>;

beforeEach(() => {
  mockFetch.mockReset();
  localStorage.clear();
});

describe('authAPI', () => {
  it('signup calls correct API', async () => {
    mockFetch.mockResolvedValueOnce({
      json: async () => ({ success: true })
    });

    const res = await authAPI.signup('a@test.com', 'user', '1234');

    expect(fetch).toHaveBeenCalledWith(
      `${API_BASE_URL}/auth/signup`,
      expect.objectContaining({
        method: 'POST'
      })
    );

    expect(res.success).toBe(true);
  });

  it('login works', async () => {
    mockFetch.mockResolvedValueOnce({
      json: async () => ({ token: 'abc' })
    });

    const res = await authAPI.login('a@test.com', '1234');
    expect(res.token).toBe('abc');
  });
});

describe('productsAPI', () => {
  test('getAll fetches products', async () => {
    mockFetch.mockResolvedValueOnce({
      json: async () => ([{ id: 1 }])
    });

    const res = await productsAPI.getAll();

    expect(fetch).toHaveBeenCalledWith(`${API_BASE_URL}/products`);
    expect(res.length).toBe(1);
  });

  test('getById fetches product by id', async () => {
    mockFetch.mockResolvedValueOnce({
      json: async () => ({ id: '1' })
    });

    const res = await productsAPI.getById('1');
    expect(res.id).toBe('1');
  });
});

describe('ordersAPI', () => {
  test('getAll calls orders API', async () => {
    localStorage.setItem('token', 'abc');

    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ([]),
    });

    const res = await ordersAPI.getAll();

    expect(fetch).toHaveBeenCalledWith(
      `${API_BASE_URL}/orders`,
      expect.objectContaining({
        headers: expect.objectContaining({
          Authorization: 'Bearer abc'
        })
      })
    );

    expect(res).toEqual([]);
  });
});


describe('wishlistAPI', () => {
  it('add product to wishlist', async () => {
    localStorage.setItem('token', 'abc');

    mockFetch.mockResolvedValueOnce({
      json: async () => ({ success: true })
    });

    const res = await wishlistAPI.add('123');

    expect(fetch).toHaveBeenCalledWith(
      `${API_BASE_URL}/wishlist/123`,
      expect.objectContaining({
        method: 'POST'
      })
    );

    expect(res.success).toBe(true);
  });
});

describe('contactAPI', () => {
  it('submits contact form', async () => {
    mockFetch.mockResolvedValueOnce({
      json: async () => ({ message: 'sent' })
    });

    const res = await contactAPI.submit({
      name: 'A',
      email: 'a@test.com',
      subject: 'Hi',
      message: 'Hello'
    });

    expect(fetch).toHaveBeenCalledWith(
      `${API_BASE_URL}/contact/submit`,
      expect.objectContaining({
        method: 'POST'
      })
    );

    expect(res.message).toBe('sent');
  });
});