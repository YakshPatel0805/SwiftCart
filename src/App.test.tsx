import { render, screen } from '@testing-library/react'
import { describe, it, expect, vi } from 'vitest'
import App from './App'

vi.mock('./pages/Home', () => ({ default: () => <div>Home Page</div> }))
vi.mock('./pages/Auth/Login', () => ({ default: () => <div>Login Page</div> }))
vi.mock('./pages/Auth/Signup', () => ({ default: () => <div>Signup Page</div> }))
vi.mock('./pages/Dashboard', () => ({ default: () => <div>Dashboard Page</div> }))
vi.mock('./pages/Cart', () => ({ default: () => <div>Cart Page</div> }))
vi.mock('./pages/Wishlist', () => ({ default: () => <div>Wishlist Page</div> }))

vi.mock('./components/Layout/Header', () => ({
  default: () => <div>Header Component</div>,
}))

vi.mock('./components/Layout/AdminHeader', () => ({
  default: () => <div>Admin Header Component</div>,
}))

vi.mock('./components/Layout/Footer', () => ({
  default: () => <div>Footer Component</div>,
}))

const mockUseAuth = vi.fn()

vi.mock('./context/AuthContext', async () => {
  const actual: any = await vi.importActual('./context/AuthContext')
  return {
    ...actual,
    useAuth: () => mockUseAuth(),
  }
})

describe('App routing and layout', () => {
  it('renders Header for normal user', () => {
    window.history.pushState({}, '', '/')
    mockUseAuth.mockReturnValue({ user: { role: 'user' } })

    render(<App />)

    expect(screen.getByText('Header Component')).toBeInTheDocument()
    expect(screen.getByText('Footer Component')).toBeInTheDocument()
    expect(screen.getByText('Home Page')).toBeInTheDocument()
  })

  it('renders AdminHeader for admin user', () => {
    window.history.pushState({}, '', '/')
    mockUseAuth.mockReturnValue({ user: { role: 'admin' } })

    render(<App />)

    expect(screen.getByText('Admin Header Component')).toBeInTheDocument()
  })

  it('renders Login page on /login route', () => {
    window.history.pushState({}, '', '/login')
    mockUseAuth.mockReturnValue({ user: null })

    render(<App />)

    expect(screen.getByText('Login Page')).toBeInTheDocument()
  })
})