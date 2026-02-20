import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import Header from './Header';
import { MemoryRouter } from 'react-router-dom';
import { vi } from 'vitest';

vi.mock('../../context/AuthContext', () => ({
  useAuth: () => ({
    user: { username: 'john', role: 'user' },
    logout: vi.fn(),
  }),
}));

vi.mock('../../context/CartContext', () => ({
  useCart: () => ({
    getTotalItems: () => 3,
  }),
}));

vi.mock('../../services/api', () => ({
  productsAPI: {
    getCategories: vi.fn().mockResolvedValue([
      { category: 'electronics', count: 5 },
      { category: 'clothing', count: 3 },
    ]),
  },
}));

const mockNavigate = vi.fn();
vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual<any>('react-router-dom');
  return {
    ...actual,
    useNavigate: () => mockNavigate,
    useLocation: () => ({ pathname: '/' }),
  };
});

const renderHeader = () => {
  render(
    <MemoryRouter>
      <Header />
    </MemoryRouter>
  );
};

describe('Header', () => {
  test('renders logo', () => {
    renderHeader();
    expect(screen.getByText('SwiftCart')).toBeInTheDocument();
  });

  test('shows cart badge', () => {
    renderHeader();
    expect(screen.getByText('3')).toBeInTheDocument();
  });

  test('opens user menu on click', () => {
    renderHeader();

    fireEvent.click(screen.getByRole('button', { name: /john/i }));

    expect(screen.getByText('Profile')).toBeInTheDocument();
    expect(screen.getByText('Orders')).toBeInTheDocument();
  });

  test('loads and shows categories', async () => {
    renderHeader();

    fireEvent.click(screen.getByText('Categories'));

    await waitFor(() => {
      expect(screen.getByText('electronics')).toBeInTheDocument();
      expect(screen.getByText('clothing')).toBeInTheDocument();
    });
  });

  test('navigates when category clicked', async () => {
    renderHeader();

    fireEvent.click(screen.getByText('Categories'));

    const cat = await screen.findByText('electronics');
    fireEvent.click(cat);

    expect(mockNavigate).toHaveBeenCalledWith('/category/electronics');
  });

  test('logout button works', () => {
    renderHeader();

    fireEvent.click(screen.getByRole('button', { name: /john/i }));
    fireEvent.click(screen.getByText('Logout'));

    expect(mockNavigate).toHaveBeenCalledWith('/');
  });
});