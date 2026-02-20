import { render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter, Routes, Route } from 'react-router-dom'
import { vi } from 'vitest'
import CategoryPage from './CategoryPage'
import { productsAPI } from '../services/api'
import { CartProvider } from '../context/CartContext'
import { WishlistProvider } from '../context/WishlistContext'
import { AuthProvider } from '../context/AuthContext'
import { Product } from '../types'

vi.mock('../services/api', () => ({
  productsAPI: {
    getAll: vi.fn(),
  },
}))

const mockedProducts: Product[] = [
  {
    id: '1',
    name: 'Product 1',
    description: 'Description 1',
    price: 10,
    image: 'image1.jpg',
    category: 'electronics',
    rating: 4,
    reviews: 10,
    inStock: true,
  },
  {
    id: '2',
    name: 'Product 2',
    description: 'Description 2',
    price: 20,
    image: 'image2.jpg',
    category: 'clothing',
    rating: 5,
    reviews: 20,
    inStock: true,
  },
  {
    id: '3',
    name: 'Product 3',
    description: 'Description 3',
    price: 30,
    image: 'image3.jpg',
    category: 'electronics',
    rating: 3,
    reviews: 5,
    inStock: true,
  },
]

const renderWithProviders = (route: string) => {
  return render(
    <AuthProvider>
      <CartProvider>
        <WishlistProvider>
          <MemoryRouter initialEntries={[route]}>
            <Routes>
              <Route path="/category/:categoryName" element={<CategoryPage />} />
            </Routes>
          </MemoryRouter>
        </WishlistProvider>
      </CartProvider>
    </AuthProvider>
  )
}

describe('CategoryPage', () => {
  it('renders all products when category is "all"', async () => {
    (productsAPI.getAll as any).mockResolvedValue(mockedProducts)

    renderWithProviders('/category/all')

    await waitFor(() => {
      expect(screen.getByText('All Products')).toBeInTheDocument()
    })

    expect(screen.getByText('Product 1')).toBeInTheDocument()
    expect(screen.getByText('Product 2')).toBeInTheDocument()
    expect(screen.getByText('Product 3')).toBeInTheDocument()
  })

  it('filters products by category', async () => {
    (productsAPI.getAll as any).mockResolvedValue(mockedProducts)

    renderWithProviders('/category/electronics')

    await waitFor(() => {
      expect(screen.getByText('Electronics')).toBeInTheDocument()
    })

    expect(screen.getByText('Product 1')).toBeInTheDocument()
    expect(screen.getByText('Product 3')).toBeInTheDocument()
    expect(screen.queryByText('Product 2')).toBeNull()
  })

   it('handles API errors gracefully', async () => {
    (productsAPI.getAll as any).mockRejectedValue(new Error('API Error'));

    render(
      <MemoryRouter initialEntries={['/category/all']}>
        <Routes>
          <Route path="/category/:categoryName" element={<CategoryPage />} />
        </Routes>
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(screen.queryByText(/Loading products/i)).toBeNull();
        })
    })
    
    it('renders loading state initially', () => {
    (productsAPI.getAll as any).mockResolvedValue([]);
    render(
      <MemoryRouter initialEntries={['/category/all']}>
        <Routes>
          <Route path="/category/:categoryName" element={<CategoryPage />} />
        </Routes>
      </MemoryRouter>
    );

    expect(screen.getByText(/Loading products/i)).toBeInTheDocument();
  });
  
})