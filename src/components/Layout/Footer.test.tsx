import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import Footer from './Footer';

describe('Footer', () => {
  const renderFooter = () =>
    render(
      <MemoryRouter>
        <Footer />
      </MemoryRouter>
    );

  test('renders company name and description', () => {
    renderFooter();

    expect(screen.getByText('SwiftCart')).toBeInTheDocument();
    expect(
      screen.getByText(/your trusted e-commerce destination/i)
    ).toBeInTheDocument();
  });

  test('renders social media links', () => {
  renderFooter();

  expect(screen.getByRole('link', { name: 'Facebook' })).toBeInTheDocument();
  expect(screen.getByRole('link', { name: 'Twitter' })).toBeInTheDocument();
  expect(screen.getByRole('link', { name: 'Instagram' })).toBeInTheDocument();
    });

  test('renders quick links', () => {
    renderFooter();

    expect(screen.getByText('Home')).toBeInTheDocument();
    expect(screen.getByText('About Us')).toBeInTheDocument();
    expect(screen.getByText('Contact')).toBeInTheDocument();
    expect(screen.getByText('Help')).toBeInTheDocument();
  });

  test('renders legal links', () => {
    renderFooter();

    expect(screen.getByText('Privacy Policy')).toBeInTheDocument();
    expect(screen.getByText('Terms of Service')).toBeInTheDocument();
    expect(screen.getByText('Shipping Policy')).toBeInTheDocument();
    expect(screen.getByText('Return Policy')).toBeInTheDocument();
  });

  test('renders copyright text', () => {
    renderFooter();

    expect(
      screen.getByText(/© 2025 SwiftCart\. All rights reserved\./i)
    ).toBeInTheDocument();
  });
});