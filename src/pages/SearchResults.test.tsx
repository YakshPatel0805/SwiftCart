import { render, screen, waitFor } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import SearchResults from './SearchResults';
import { productsAPI } from '../services/api';
import { useSearchParams } from 'react-router-dom';

vi.mock('../components/Product/ProductGrid', () => ({
  default: ({ products }: any) => (
    <div data-testid="product-grid">
      {products.map((p: any) => (
        <div key={p.id}>{p.name}</div>
      ))}
    </div>
  ),
}));

vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual<any>('react-router-dom');
  return {
    ...actual,
    useSearchParams: vi.fn(),
  };
});

vi.mock('../services/api', () => ({
  productsAPI: {
    getAll: vi.fn(),
  },
}));

const mockedProducts = [
  {
    id: '1',
    name: 'Phone',
    description: 'Smart phone',
    category: 'electronics',
  },
  {
    id: '2',
    name: 'Shirt',
    description: 'Cotton shirt',
    category: 'clothing',
  },
  {
    id: '3',
    name: 'Laptop',
    description: 'Gaming laptop',
    category: 'electronics',
  },
];

describe('SearchResults Page', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('shows filtered products based on search query', async () => {
    (useSearchParams as any).mockReturnValue([
      new URLSearchParams({ q: 'electronics' }),
    ]);

    (productsAPI.getAll as any).mockResolvedValue(mockedProducts);

    render(<SearchResults />);

    await waitFor(() =>
      expect(screen.getByText(/search results for "electronics"/i)).toBeInTheDocument()
    );

    expect(screen.getByText('Phone')).toBeInTheDocument();
    expect(screen.getByText('Laptop')).toBeInTheDocument();
    expect(screen.queryByText('Shirt')).not.toBeInTheDocument();
  });

  it('shows no products message when nothing matches', async () => {
    (useSearchParams as any).mockReturnValue([
      new URLSearchParams({ q: 'toys' }),
    ]);

    (productsAPI.getAll as any).mockResolvedValue(mockedProducts);

    render(<SearchResults />);

    await waitFor(() =>
      expect(screen.getByText(/no products found/i)).toBeInTheDocument()
    );

    expect(
      screen.getByText(/try different keywords/i)
    ).toBeInTheDocument();
  });
});