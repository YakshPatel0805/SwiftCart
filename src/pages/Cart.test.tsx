import { render, screen, fireEvent } from '@testing-library/react'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import Cart from './Cart'

// mocks
const mockNavigate = vi.fn()
const mockUpdateQuantity = vi.fn()
const mockRemoveFromCart = vi.fn()
const mockGetTotalPrice = vi.fn()

vi.mock('react-router-dom', () => ({
  useNavigate: () => mockNavigate,
}))

const mockUseCart = vi.fn()
vi.mock('../context/CartContext', () => ({
  useCart: () => mockUseCart(),
}))

const mockUseAuth = vi.fn()
vi.mock('../context/AuthContext', () => ({
  useAuth: () => mockUseAuth(),
}))

const mockItem = {
  product: {
    id: '1',
    name: 'Laptop',
    description: 'Gaming laptop',
    price: 1000,
    image: 'test.jpg',
  },
  quantity: 2,
}

describe('Cart component', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('renders empty cart message', () => {
    mockUseCart.mockReturnValue({
      items: [],
      updateQuantity: mockUpdateQuantity,
      removeFromCart: mockRemoveFromCart,
      getTotalPrice: mockGetTotalPrice,
    })

    mockUseAuth.mockReturnValue({ user: null })

    render(<Cart />)

    expect(screen.getByText(/your cart is empty/i)).toBeInTheDocument()
    expect(screen.getByText(/continue shopping/i)).toBeInTheDocument()
  })

  it('renders cart items', () => {
    mockUseCart.mockReturnValue({
      items: [mockItem],
      updateQuantity: mockUpdateQuantity,
      removeFromCart: mockRemoveFromCart,
      getTotalPrice: () => 2000,
    })

    mockUseAuth.mockReturnValue({ user: null })

    render(<Cart />)

    expect(screen.getByText('Laptop')).toBeInTheDocument()
    expect(screen.getByText('Gaming laptop')).toBeInTheDocument()
    expect(screen.getByText('$1000.00')).toBeInTheDocument()
    expect(screen.getByText('2')).toBeInTheDocument()
  })

 it('increases quantity when + clicked', () => {
  mockUseCart.mockReturnValue({
    items: [mockItem],
    updateQuantity: mockUpdateQuantity,
    removeFromCart: mockRemoveFromCart,
    getTotalPrice: () => 2000,
  })

  mockUseAuth.mockReturnValue({ user: null })

  render(<Cart />)

  const plusButton = screen.getByTestId(`increase-${mockItem.product.id}`)
  fireEvent.click(plusButton)

  expect(mockUpdateQuantity).toHaveBeenCalledWith(mockItem.product.id, mockItem.quantity + 1)
})

  it('removes item when trash clicked', () => {
    mockUseCart.mockReturnValue({
      items: [mockItem],
      updateQuantity: mockUpdateQuantity,
      removeFromCart: mockRemoveFromCart,
      getTotalPrice: () => 2000,
    })

    mockUseAuth.mockReturnValue({ user: null })

    render(<Cart />)

    const trashButton = screen.getByTestId(`remove-${mockItem.product.id}`)
    fireEvent.click(trashButton)
    expect(mockRemoveFromCart).toHaveBeenCalledWith(mockItem.product.id)
        expect(mockRemoveFromCart).toHaveBeenCalledWith('1')
    })

  it('redirects to login when checkout and not logged in', () => {
    mockUseCart.mockReturnValue({
      items: [mockItem],
      updateQuantity: mockUpdateQuantity,
      removeFromCart: mockRemoveFromCart,
      getTotalPrice: () => 2000,
    })

    mockUseAuth.mockReturnValue({ user: null })

    render(<Cart />)

    fireEvent.click(screen.getByText(/proceed to checkout/i))

    expect(mockNavigate).toHaveBeenCalledWith('/login')
  })

  it('redirects to checkout when logged in', () => {
    mockUseCart.mockReturnValue({
      items: [mockItem],
      updateQuantity: mockUpdateQuantity,
      removeFromCart: mockRemoveFromCart,
      getTotalPrice: () => 2000,
    })

    mockUseAuth.mockReturnValue({ user: { id: 'u1' } })

    render(<Cart />)

    fireEvent.click(screen.getByText(/proceed to checkout/i))

    expect(mockNavigate).toHaveBeenCalledWith('/checkout')
  })
})