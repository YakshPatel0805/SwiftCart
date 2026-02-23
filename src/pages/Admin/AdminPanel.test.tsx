import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import AdminPanel from './AdminPanel';
import { BrowserRouter } from 'react-router-dom';

global.fetch = vi.fn();

const mockNavigate = vi.fn();

vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual<any>('react-router-dom');
  return {
    ...actual,
    useNavigate: () => mockNavigate,
  };
});


global.File = class File extends Blob {
  name: string;
  lastModified: number;

  constructor(parts: any[], filename: string, properties?: any) {
    super(parts, properties);
    this.name = filename;
    this.lastModified = Date.now();
  }
} as any;

describe('AdminPanel (Vitest)', () => {

  beforeAll(() => {
    global.URL.createObjectURL = vi.fn(() => 'mock-url');
  });

  afterAll(() => {
    vi.restoreAllMocks();
  });

  beforeEach(() => {
    vi.clearAllMocks();
    localStorage.setItem('token', 'fake-token');
  });

  const renderComponent = () => {
    render(
      <BrowserRouter>
        <AdminPanel />
      </BrowserRouter>
    );
  };


  it('updates UI when file is selected', () => {
    renderComponent();

    const input = screen.getByLabelText(/csv file/i);
    const file = new File(['test'], 'products.csv', { type: 'text/csv' });

    fireEvent.change(input, {
      target: { files: [file] },
    });

    expect(screen.getByText(/products.csv/i)).toBeInTheDocument();
  });


  it('uploads CSV successfully', async () => {
    (fetch as any).mockResolvedValueOnce({
      ok: true,
      json: async () => ({ message: 'Upload successful' }),
    });

    renderComponent();

    const input = screen.getByLabelText(/csv file/i);
    const file = new File(['data'], 'products.csv', { type: 'text/csv' });

    fireEvent.change(input, {
      target: { files: [file] },
    });

    // fireEvent.click(screen.getByText(/upload products/i));
    fireEvent.click(screen.getByRole('button', { name: /upload products/i }));

    await waitFor(() => {
      expect(screen.getByText(/upload successful/i)).toBeInTheDocument();
    });
  });


  it('shows error when upload fails', async () => {
    (fetch as any).mockResolvedValueOnce({
      ok: false,
      json: async () => ({ message: 'Upload failed' }),
    });

    renderComponent();

    const input = screen.getByLabelText(/csv file/i);
    const file = new File(['data'], 'products.csv', { type: 'text/csv' });

    fireEvent.change(input, {
      target: { files: [file] },
    });

    // fireEvent.click(screen.getByText(/upload products/i));
        fireEvent.click(screen.getByRole('button', { name: /upload products/i }));



    await waitFor(() => {
      expect(screen.getByText(/upload failed/i)).toBeInTheDocument();
    });
  });


  it('triggers CSV template download', () => {
    renderComponent();

    const createSpy = vi.spyOn(document, 'createElement');

    fireEvent.click(screen.getByText(/download csv template/i));

    expect(createSpy).toHaveBeenCalledWith('a');
  });

  
  it('toggles add product form', () => {
    renderComponent();

    fireEvent.click(
      screen.getByRole('button', { name: /show form/i })
    );

    expect(
      screen.getByLabelText(/product name/i)
    ).toBeInTheDocument();

    fireEvent.click(
      screen.getByRole('button', { name: /hide form/i })
    );

    expect(
      screen.queryByLabelText(/product name/i)
    ).not.toBeInTheDocument();
  });

  it('adds product successfully', async () => {
  (fetch as any).mockResolvedValueOnce({
    ok: true,
    json: async () => ({}),
  });

  renderComponent();

  fireEvent.click(
    screen.getByRole('button', { name: /show form/i })
  );

  fireEvent.change(screen.getByLabelText(/product name/i), {
    target: { value: 'Test Product' },
  });

  fireEvent.change(screen.getByLabelText(/^price/i), {
    target: { value: '100' },
  });

  fireEvent.change(screen.getByLabelText(/category/i), {
    target: { value: 'electronics' },
  });

  fireEvent.change(screen.getByLabelText(/image url/i), {
    target: { value: 'https://img.com' },
  });

  fireEvent.change(screen.getByLabelText(/description/i), {
    target: { value: 'Nice product' },
  });

  fireEvent.change(screen.getByLabelText(/rating/i), {
    target: { value: '4.5' },
  });

  fireEvent.change(screen.getByLabelText(/reviews/i), {
    target: { value: '10' },
  });

  fireEvent.change(screen.getByLabelText(/in stock/i), {
    target: { value: 'true' },
  });

  fireEvent.click(
    screen.getByRole('button', { name: /^add product$/i })
  );

  await waitFor(() => {
    expect(
      screen.getByText(/product added successfully/i)
    ).toBeInTheDocument();
  });
});

  
  it('navigates to products page', () => {
    renderComponent();

    fireEvent.click(screen.getByText(/view all products/i));
    expect(mockNavigate).toHaveBeenCalledWith('/admin/products');
  });


  it('navigates to orders page', () => {
    renderComponent();

    fireEvent.click(screen.getByText(/view orders/i));
    expect(mockNavigate).toHaveBeenCalledWith('/admin/orders');
  });
});