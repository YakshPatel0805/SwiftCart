import { render, screen, fireEvent, within } from '@testing-library/react'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { MemoryRouter } from 'react-router-dom'
import AdminHeader from './AdminHeader'
import type { User } from '../../types'

const mockNavigate = vi.fn()

vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual<any>('react-router-dom')
  return {
    ...actual,
    useNavigate: () => mockNavigate,
  }
})

const mockLogout = vi.fn()

vi.mock('../../context/AuthContext', () => ({
  useAuth: () => ({
    user: {
      id: '1',
      email: 'admin@test.com',
      username: 'admin',
      role: 'admin',
    } as User,
    logout: mockLogout,
  }),
}))

describe('AdminHeader', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  function renderComponent() {
    return render(
      <MemoryRouter>
        <AdminHeader />
      </MemoryRouter>
    )
  }

  it('renders username from auth context', () => {
    renderComponent()
    expect(screen.getByText('admin')).toBeInTheDocument()
  })

    it('opens dropdown menu when user icon is clicked', () => {
    renderComponent()

    fireEvent.click(screen.getByRole('button'))

    const dropdown = screen.getByText('Logout').parentElement!

    expect(within(dropdown).getByText('Admin Panel')).toBeInTheDocument()
    expect(within(dropdown).getByText('Profile')).toBeInTheDocument()
    expect(within(dropdown).getByText('Logout')).toBeInTheDocument()
    })

  it('closes dropdown when clicking outside', () => {
    renderComponent()

    fireEvent.click(screen.getByRole('button'))
    expect(screen.getByText('Logout')).toBeInTheDocument()

    fireEvent.mouseDown(document.body)
    expect(screen.queryByText('Logout')).not.toBeInTheDocument()
  })

  it('calls logout and navigates to login on logout click', () => {
    renderComponent()

    fireEvent.click(screen.getByRole('button'))
    fireEvent.click(screen.getByText('Logout'))

    expect(mockLogout).toHaveBeenCalledOnce()
    expect(mockNavigate).toHaveBeenCalledWith('/login')
  })
})