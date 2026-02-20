import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import Checkout from './Checkout'
import { BrowserRouter } from 'react-router-dom'
import { ordersAPI } from '../services/api'
import { useCart } from '../context/CartContext'
import { useAuth } from '../context/AuthContext'

vi.mock('../services/api', () => ({
  ordersAPI: {
    create: vi.fn(),
  },
}))

vi.mock('../context/CartContext', () => ({
  useCart: vi.fn(),
}))

vi.mock('../context/AuthContext', () => ({
  useAuth: vi.fn(),
}))

const mockNavigate = vi.fn()

vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual<any>('react-router-dom')
  return {
    ...actual,
    useNavigate: () => mockNavigate,
  }
})

const mockCartItems = [
  {
    product: {
      id: '1',
      name: 'Product 1',
      price: 10,
      image: 'img.jpg',
    },
    quantity: 2,
  },
]

describe('Checkout', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('shows sign in message if user not logged in', () => {
    ;(useAuth as any).mockReturnValue({ user: null })
    ;(useCart as any).mockReturnValue({
      items: mockCartItems,
      getTotalPrice: () => 20,
      clearCart: vi.fn(),
    })

    render(<Checkout />)

    expect(screen.getByText(/please sign in/i)).toBeInTheDocument()
  })

  it('shows empty cart message', () => {
    ;(useAuth as any).mockReturnValue({ user: { email: 'test@test.com' } })
    ;(useCart as any).mockReturnValue({
      items: [],
      getTotalPrice: () => 0,
      clearCart: vi.fn(),
    })

    render(<Checkout />)

    expect(screen.getByText(/your cart is empty/i)).toBeInTheDocument()
  })

  it('renders shipping form when logged in and cart has items', () => {
    ;(useAuth as any).mockReturnValue({ user: { email: 'test@test.com' } })
    ;(useCart as any).mockReturnValue({
      items: mockCartItems,
      getTotalPrice: () => 20,
      clearCart: vi.fn(),
    })

    render(
      <BrowserRouter>
        <Checkout />
      </BrowserRouter>
    )

    expect(screen.getByText('Shipping Information')).toBeInTheDocument()
    expect(screen.getByText('Order Summary')).toBeInTheDocument()
    expect(screen.getByText('Product 1')).toBeInTheDocument()
  })

  it('submits order successfully', async () => {
    const clearCart = vi.fn()

    ;(useAuth as any).mockReturnValue({ user: { email: 'test@test.com' } })
    ;(useCart as any).mockReturnValue({
      items: mockCartItems,
      getTotalPrice: () => 20,
      clearCart,
    })

    ;(ordersAPI.create as any).mockResolvedValue({ success: true })

    render(
      <BrowserRouter>
        <Checkout />
      </BrowserRouter>
    )

    fireEvent.change(screen.getByLabelText(/full name/i), {
    target: { value: 'John Doe' },
    });

    fireEvent.change(screen.getByLabelText(/email address/i), {
    target: { value: 'test@test.com' },
    });

    fireEvent.change(screen.getByLabelText(/^address$/i), {
    target: { value: 'Street 1' },
    });

    fireEvent.change(screen.getByLabelText(/city/i), {
    target: { value: 'NY' },
    });

    fireEvent.change(screen.getByLabelText(/state/i), {
    target: { value: 'NY' },
    });

    fireEvent.change(screen.getByLabelText(/zip code/i), {
    target: { value: '12345' },
    });
    
    fireEvent.change(screen.getByLabelText(/country/i), {
    target: { value: 'United States' },
    });

      fireEvent.click(
    screen.getByRole('button', { name: /continue to payment/i })
    );

    // await waitFor(() => {
    //   screen.getByRole('heading', { name: /payment information/i })
    // })

    // fireEvent.click(screen.getByText(/place order/i))

    // await waitFor(() => {
    //   expect(ordersAPI.create).toHaveBeenCalled()
    // })
  })
})