import express from 'express';
import { sendContactEmail } from '../utils/emailService.js';

const router = express.Router();

router.post('/submit', async (req, res) => {
  try {
    const { name, email, subject, message } = req.body;

    // Validate input
    if (!name || !email || !subject || !message) {
      return res.status(400).json({ message: 'All fields are required' });
    }

    // Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ message: 'Invalid email format' });
    }

    // Send contact emails
    const emailSent = await sendContactEmail({
      name,
      email,
      subject,
      message
    });

    if (emailSent) {
      res.status(200).json({ 
        message: 'Your message has been sent successfully. We will get back to you soon!' 
      });
    } else {
      res.status(500).json({ 
        message: 'Failed to send message. Please try again later.' 
      });
    }
  } catch (error) {
    console.error('Contact form error:', error);
    res.status(500).json({ 
      message: 'Server error. Please try again later.',
      error: error.message 
    });
  }
});

export default router;
