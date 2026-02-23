import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
  authAPI,
  productsAPI,
  ordersAPI,
  wishlistAPI,
  contactAPI
} from './api';

global.fetch = vi.fn();

describe('API services', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    localStorage.clear();
  });


  it('authAPI.signup', async () => {
    (fetch as any).mockResolvedValueOnce({
      json: async () => ({ success: true }),
    });

    const res = await authAPI.signup('a@test.com', 'user', '1234', 'user');

    expect(fetch).toHaveBeenCalledWith(
      'http://localhost:5000/api/auth/signup',
      expect.objectContaining({
        method: 'POST',
      })
    );
    expect(res.success).toBe(true);
  });

  it('authAPI.login', async () => {
    (fetch as any).mockResolvedValueOnce({
      json: async () => ({ token: 'abc' }),
    });

    const res = await authAPI.login('a@test.com', '1234');

    expect(fetch).toHaveBeenCalledWith(
      'http://localhost:5000/api/auth/login',
      expect.objectContaining({
        method: 'POST',
      })
    );
    expect(res.token).toBe('abc');
  });

  it('authAPI.verifyResetToken', async () => {
    (fetch as any).mockResolvedValueOnce({
      json: async () => ({ valid: true }),
    });

    const res = await authAPI.verifyResetToken('token123');

    expect(fetch).toHaveBeenCalledWith(
      'http://localhost:5000/api/auth/verify-reset-token/token123'
    );
    expect(res.valid).toBe(true);
  });

  it('authAPI.changePassword', async () => {
    localStorage.setItem('token', 'abc');

    (fetch as any).mockResolvedValueOnce({
      json: async () => ({ success: true }),
    });

    const res = await authAPI.changePassword('a@test.com', 'old', 'new', 'new');

    expect(fetch).toHaveBeenCalled();
    expect(res.success).toBe(true);
  });


  it('productsAPI.getAll', async () => {
    (fetch as any).mockResolvedValueOnce({
      json: async () => ([]),
    });

    const res = await productsAPI.getAll();

    expect(fetch).toHaveBeenCalledWith('http://localhost:5000/api/products');
    expect(res).toEqual([]);
  });

  it('productsAPI.getById', async () => {
    (fetch as any).mockResolvedValueOnce({
      json: async () => ({ id: 1 }),
    });

    const res = await productsAPI.getById('1');

    expect(fetch).toHaveBeenCalledWith('http://localhost:5000/api/products/1');
    expect(res.id).toBe(1);
  });

  it('productsAPI.getCategories', async () => {
    (fetch as any).mockResolvedValueOnce({
      json: async () => (['electronics']),
    });

    const res = await productsAPI.getCategories();

    expect(fetch).toHaveBeenCalledWith('http://localhost:5000/api/products/categories');
    expect(res[0]).toBe('electronics');
  });

  it('productsAPI.update', async () => {
    localStorage.setItem('token', 'abc');

    (fetch as any).mockResolvedValueOnce({
      ok: true,
      json: async () => ({ updated: true }),
    });

    const res = await productsAPI.update('1', { name: 'Test' });

    expect(res.updated).toBe(true);
  });

  it('productsAPI.delete', async () => {
    localStorage.setItem('token', 'abc');

    (fetch as any).mockResolvedValueOnce({
      ok: true,
      json: async () => ({ deleted: true }),
    });

    const res = await productsAPI.delete('1');

    expect(res.deleted).toBe(true);
  });


  it('ordersAPI.getAll', async () => {
    localStorage.setItem('token', 'abc');

    (fetch as any).mockResolvedValueOnce({
      ok: true,
      json: async () => ([]),
    });

    const res = await ordersAPI.getAll();

    expect(res).toEqual([]);
  });

  it('ordersAPI.getAllAdmin', async () => {
    localStorage.setItem('token', 'abc');

    (fetch as any).mockResolvedValueOnce({
      ok: true,
      json: async () => ([]),
    });

    const res = await ordersAPI.getAllAdmin();

    expect(res).toEqual([]);
  });

  it('ordersAPI.getById', async () => {
    localStorage.setItem('token', 'abc');

    (fetch as any).mockResolvedValueOnce({
      json: async () => ({ id: 1 }),
    });

    const res = await ordersAPI.getById('1');

    expect(res.id).toBe(1);
  });

  it('ordersAPI.create', async () => {
    localStorage.setItem('token', 'abc');

    (fetch as any).mockResolvedValueOnce({
      ok: true,
      json: async () => ({ created: true }),
    });

    const res = await ordersAPI.create({ items: [] });

    expect(res.created).toBe(true);
  });

  it('ordersAPI.cancel', async () => {
    localStorage.setItem('token', 'abc');

    (fetch as any).mockResolvedValueOnce({
      ok: true,
      json: async () => ({ cancelled: true }),
    });

    const res = await ordersAPI.cancel('1');

    expect(res.cancelled).toBe(true);
  });

  it('ordersAPI.updateStatus', async () => {
    localStorage.setItem('token', 'abc');

    (fetch as any).mockResolvedValueOnce({
      ok: true,
      json: async () => ({ status: 'shipped' }),
    });

    const res = await ordersAPI.updateStatus('1', 'shipped');

    expect(res.status).toBe('shipped');
  });


  it('wishlistAPI.get', async () => {
    localStorage.setItem('token', 'abc');

    (fetch as any).mockResolvedValueOnce({
      json: async () => ([]),
    });

    const res = await wishlistAPI.get();

    expect(res).toEqual([]);
  });

  it('wishlistAPI.add', async () => {
    localStorage.setItem('token', 'abc');

    (fetch as any).mockResolvedValueOnce({
      json: async () => ({ added: true }),
    });

    const res = await wishlistAPI.add('1');

    expect(res.added).toBe(true);
  });

  it('wishlistAPI.remove', async () => {
    localStorage.setItem('token', 'abc');

    (fetch as any).mockResolvedValueOnce({
      json: async () => ({ removed: true }),
    });

    const res = await wishlistAPI.remove('1');

    expect(res.removed).toBe(true);
  });


  it('contactAPI.submit', async () => {
    (fetch as any).mockResolvedValueOnce({
      json: async () => ({ success: true }),
    });

    const res = await contactAPI.submit({
      name: 'Test',
      email: 'a@test.com',
      subject: 'Hello',
      message: 'Test msg'
    });

    expect(res.success).toBe(true);
  });
});