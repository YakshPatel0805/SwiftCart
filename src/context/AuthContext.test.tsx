import { render, screen, act } from '@testing-library/react'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import React from 'react'
import { AuthProvider, useAuth } from './AuthContext'
import { authAPI } from '../services/api'
import type { User } from '../types'


vi.mock('../services/api', () => ({
  authAPI: {
    login: vi.fn(),
    signup: vi.fn(),
  },
}))

function TestComponent() {
  const { user, login, signup, logout, isLoading } = useAuth()

  return (
    <div>
      <div data-testid="loading">{isLoading ? 'loading' : 'done'}</div>
      <div data-testid="user">{user ? user.email : 'no-user'}</div>

      <button onClick={() => login('test@mail.com', '123456')}>login</button>
      <button onClick={() => signup('new@mail.com', 'newuser', '123456')}>signup</button>
      <button onClick={logout}>logout</button>
    </div>
  )
}

describe('AuthContext', () => {
  beforeEach(() => {
    localStorage.clear()
    vi.clearAllMocks()
  })

  it('loads user from localStorage on init', async () => {
    const mockUser: User = {
      id: '1',
      email: 'saved@mail.com',
      username: 'saveduser',
      role: 'user',
    }

    localStorage.setItem('user', JSON.stringify(mockUser))
    localStorage.setItem('token', 'token123')

    render(
      <AuthProvider>
        <TestComponent />
      </AuthProvider>
    )

    expect(await screen.findByText('done')).toBeInTheDocument()
    expect(screen.getByTestId('user').textContent).toBe('saved@mail.com')
  })

  it('login sets user and token', async () => {
    ;(authAPI.login as any).mockResolvedValue({
      token: 'abc123',
      user: {
        id: '2',
        email: 'test@mail.com',
        username: 'testuser',
        role: 'user',
      },
    })

    render(
      <AuthProvider>
        <TestComponent />
      </AuthProvider>
    )

    await act(async () => {
      screen.getByText('login').click()
    })

    expect(localStorage.getItem('token')).toBe('abc123')
    expect(JSON.parse(localStorage.getItem('user') || '{}').email).toBe('test@mail.com')
    expect(screen.getByTestId('user').textContent).toBe('test@mail.com')
  })

  it('signup sets user and token', async () => {
    ;(authAPI.signup as any).mockResolvedValue({
      token: 'signup123',
      user: {
        id: '3',
        email: 'new@mail.com',
        username: 'newuser',
        role: 'user',
      },
    })

    render(
      <AuthProvider>
        <TestComponent />
      </AuthProvider>
    )

    await act(async () => {
      screen.getByText('signup').click()
    })

    expect(localStorage.getItem('token')).toBe('signup123')
    expect(screen.getByTestId('user').textContent).toBe('new@mail.com')
  })

  it('logout clears user and storage', async () => {
    const mockUser: User = {
      id: '1',
      email: 'logout@mail.com',
      username: 'logoutuser',
      role: 'user',
    }

    localStorage.setItem('user', JSON.stringify(mockUser))
    localStorage.setItem('token', 'token123')

    render(
      <AuthProvider>
        <TestComponent />
      </AuthProvider>
    )

    await act(async () => {
      screen.getByText('logout').click()
    })

    expect(localStorage.getItem('user')).toBeNull()
    expect(localStorage.getItem('token')).toBeNull()
    expect(screen.getByTestId('user').textContent).toBe('no-user')
  })
})