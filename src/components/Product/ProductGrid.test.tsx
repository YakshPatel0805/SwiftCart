import React from 'react'
import { render, screen } from '@testing-library/react'
import { describe, it, expect, vi } from 'vitest'
import ProductGrid from './ProductGrid'
import { Product } from '../../types'

vi.mock('./ProductCard', () => ({
  default: ({ product }: { product: Product }) => (
    <div data-testid="product-card">{product.name}</div>
  ),
}))

const mockProducts: Product[] = [
  {
    id: '1',
    name: 'Test Product 1',
    price: 100,
    image: 'test1.jpg',
    category: 'electronics',
    description: 'desc',
    rating: 4.5,
    reviews: 10,
    inStock: true
  },
  {
    id: '2',
    name: 'Test Product 2',
    price: 200,
    image: 'test2.jpg',
    category: 'fashion',
    description: 'desc',
    rating: 4.0,
    reviews: 5,
    inStock: true
  }
]

describe('ProductGrid', () => {
  it('renders title', () => {
    render(<ProductGrid products={[]} title="Featured Products" />)
    expect(screen.getByText('Featured Products')).toBeInTheDocument()
  })

  it('shows empty message when no products', () => {
    render(<ProductGrid products={[]} title="Empty Category" />)
    expect(
      screen.getByText('No products found in this category.')
    ).toBeInTheDocument()
  })

  it('renders product cards when products exist', () => {
    render(<ProductGrid products={mockProducts} title="Products" />)

    const cards = screen.getAllByTestId('product-card')
    expect(cards.length).toBe(2)

    expect(screen.getByText('Test Product 1')).toBeInTheDocument()
    expect(screen.getByText('Test Product 2')).toBeInTheDocument()
  })
})