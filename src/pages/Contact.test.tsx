import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { describe, it, expect, vi } from 'vitest';
import Contact from './Contact';
import { contactAPI } from '../services/api';

vi.mock('../services/api', () => ({
  contactAPI: {
    submit: vi.fn(),
  },
}));

describe('Contact', () => {
  it('submits contact form successfully', async () => {
    (contactAPI.submit as any).mockResolvedValue({
      message: 'success',
    });

    render(<Contact />);

    fireEvent.change(screen.getByLabelText(/name/i), {
      target: { value: 'John Doe' },
    });

    fireEvent.change(screen.getByLabelText(/email/i), {
      target: { value: 'john@test.com' },
    });

    fireEvent.change(screen.getByLabelText(/subject/i), {
      target: { value: 'Help' },
    });

    fireEvent.change(screen.getByLabelText(/message/i), {
      target: { value: 'I need support' },
    });

    fireEvent.click(screen.getByRole('button', { name: /send message/i }));

    await waitFor(() => {
      expect(contactAPI.submit).toHaveBeenCalledTimes(1);
    });

    expect(
      await screen.findByText(/thank you for your message/i)
    ).toBeInTheDocument();
  });
});