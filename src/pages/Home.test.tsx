import { render, screen } from '@testing-library/react';
import { describe, it, expect, vi } from 'vitest';
import Home from './Home';

// mock useNavigate
const mockNavigate = vi.fn();

vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual<any>('react-router-dom');
  return {
    ...actual,
    useNavigate: () => mockNavigate,
  };
});

describe('Home Page', () => {
  it('renders hero section correctly', () => {
    render(<Home />);

    expect(screen.getByText(/welcome to swiftcart/i)).toBeInTheDocument();
    expect(screen.getByText(/shop now/i)).toBeInTheDocument();
  });

  it('renders all feature titles', () => {
    render(<Home />);

    expect(screen.getAllByText(/quality products/i).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/free shipping/i).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/secure payment/i).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/24\/7 support/i).length).toBeGreaterThan(0);
  });

  it('renders categories (duplicated list)', () => {
    render(<Home />);

    const clothingItems = screen.getAllByText('Clothing');
    expect(clothingItems.length).toBeGreaterThan(1);

    const electronicsItems = screen.getAllByText('Electronics');
    expect(electronicsItems.length).toBeGreaterThan(1);
  });

  it('renders View All Products button', () => {
    render(<Home />);

    const button = screen.getByRole('button', { name: /view all products/i });
    expect(button).toBeInTheDocument();
  });

  it('navigates when Shop Now is clicked', () => {
    render(<Home />);

    screen.getByText(/shop now/i).click();

    expect(mockNavigate).toHaveBeenCalledWith('/category/clothing');
  });

  it('navigates when View All Products is clicked', () => {
    render(<Home />);

    screen.getByText(/view all products/i).click();

    expect(mockNavigate).toHaveBeenCalledWith('/category/all');
  });
});