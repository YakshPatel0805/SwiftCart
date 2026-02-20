import { render, screen, waitFor, fireEvent } from '@testing-library/react'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import AdminProductsView from './AdminProductsView'
import { productsAPI } from '../services/api'

vi.mock('../services/api', () => ({
  productsAPI: {
    getAll: vi.fn(),
    getCategories: vi.fn(),
    update: vi.fn(),
    delete: vi.fn()
  }
}))

const mockProducts = [
  {
    id: '1',
    name: 'Laptop',
    description: 'Gaming laptop',
    category: 'electronics',
    price: 1000,
    image: 'img.jpg',
    inStock: true,
    rating: 4.5,
    reviews: 10
  },
  {
    id: '2',
    name: 'Shirt',
    description: 'Cotton shirt',
    category: 'clothing',
    price: 50,
    image: 'img2.jpg',
    inStock: false,
    rating: 3.5,
    reviews: 5
  }
]

const mockCategories = [
  { category: 'electronics', count: 1 },
  { category: 'clothing', count: 1 }
]

describe('AdminProductsView', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    ;(productsAPI.getAll as any).mockResolvedValue(mockProducts)
    ;(productsAPI.getCategories as any).mockResolvedValue(mockCategories)
  })

  it('shows loading initially', () => {
    render(<AdminProductsView />)
    expect(screen.getByText(/loading products/i)).toBeInTheDocument()
  })

  it('renders products after load', async () => {
    render(<AdminProductsView />)

    expect(await screen.findByText('Laptop')).toBeInTheDocument()
    expect(screen.getByText('Shirt')).toBeInTheDocument()
  })

  it('filters by category', async () => {
    render(<AdminProductsView />)

    await screen.findByText('Laptop')

    const electronicsBtn = screen.getByRole('button', { name: /electronics/i })
    fireEvent.click(electronicsBtn)

    expect(screen.getByText('Laptop')).toBeInTheDocument()
    expect(screen.queryByText('Shirt')).toBeNull()
  })

  it('filters by search', async () => {
    render(<AdminProductsView />)

    await screen.findByText('Laptop')

    fireEvent.change(screen.getByPlaceholderText(/search products/i), {
      target: { value: 'shirt' }
    })

    expect(screen.getByText('Shirt')).toBeInTheDocument()
    expect(screen.queryByText('Laptop')).toBeNull()
  })

  it('opens edit modal on edit click', async () => {
    render(<AdminProductsView />)

    await screen.findByText('Laptop')

    const editButtons = screen.getAllByTitle('Edit product')
    fireEvent.click(editButtons[0])

    expect(screen.getByText('Edit Product')).toBeInTheDocument()
    expect(screen.getByDisplayValue('Laptop')).toBeInTheDocument()
  })

  it('calls delete API on delete click', async () => {
    vi.spyOn(window, 'confirm').mockReturnValue(true)

    render(<AdminProductsView />)

    await screen.findByText('Laptop')

    const deleteButtons = screen.getAllByTitle('Delete product')
    fireEvent.click(deleteButtons[0])

    await waitFor(() => {
      expect(productsAPI.delete).toHaveBeenCalledWith('1')
    })
  })
})