import { render, screen, fireEvent } from '@testing-library/react'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import AdminOrdersView from './AdminOrdersView'
import { ordersAPI } from '../services/api'

vi.mock('../services/api', () => ({
  ordersAPI: {
    getAllAdmin: vi.fn(),
    updateStatus: vi.fn()
  }
}))

const mockOrders = [
  {
    _id: 'order1',
    status: 'pending',
    total: 100,
    createdAt: new Date().toISOString(),
    userId: {
      _id: 'user1',
      email: 'john@example.com'
    },
    shippingAddress: {
      name: 'John Doe',
      email: 'john@example.com',
      address: 'Street 1',
      city: 'NY',
      state: 'NY',
      zipcode: '12345',
      country: 'USA'
    },
    items: [
      {
        quantity: 2,
        product: {
          name: 'Laptop',
          price: 50,
          image: 'img.jpg'
        }
      }
    ]
  }
]

describe('AdminOrdersView', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('renders orders after loading', async () => {
    ;(ordersAPI.getAllAdmin as any).mockResolvedValue(mockOrders)

    render(<AdminOrdersView />)

    expect(screen.getByText('Loading orders...')).toBeInTheDocument()

    expect(await screen.findByText('Order Management')).toBeInTheDocument()

    const prices = await screen.findAllByText('$100.00')
    expect(prices.length).toBeGreaterThan(0)

    const emails = await screen.findAllByText('john@example.com')
    expect(emails.length).toBeGreaterThan(0)
  })

  it('expands order on click', async () => {
    ;(ordersAPI.getAllAdmin as any).mockResolvedValue(mockOrders)

    render(<AdminOrdersView />)

    const orderId = await screen.findByText('order1')
    fireEvent.click(orderId)

    expect(await screen.findByText('Customer Information')).toBeInTheDocument()

    const names = await screen.findAllByText('John Doe')
    expect(names.length).toBeGreaterThan(0)

    expect(await screen.findByText('Laptop')).toBeInTheDocument()
  })

  it('updates order status', async () => {
    ;(ordersAPI.getAllAdmin as any).mockResolvedValue(mockOrders)
    ;(ordersAPI.updateStatus as any).mockResolvedValue({})

    render(<AdminOrdersView />)

    const orderId = await screen.findByText('order1')
    fireEvent.click(orderId)

    const shipButton = await screen.findByText('Mark as Shipped')
    fireEvent.click(shipButton)

    expect(ordersAPI.updateStatus).toHaveBeenCalledWith('order1', 'shipped')
  })
})