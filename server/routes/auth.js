import express from 'express';
import jwt from 'jsonwebtoken';
import User from '../models/User.js';
import { authenticateToken } from '../middleware/auth.js';

const router = express.Router();

router.post('/signup', async (req, res) => {
  try {
    const { email, username, password } = req.body;

    const existingUser = await User.findOne({ $or: [{ email }, { username }] });
    if (existingUser) {
      return res.status(400).json({ message: 'User already exists' });
    }

    // Check if signup credentials match admin credentials
    const isAdminSignup = email === 'admin@gmail.com' && username === 'admin' && password === 'admin123';
    
    const user = new User({ 
      email, 
      username, 
      password,
      role: isAdminSignup ? 'admin' : 'user'
    });
    await user.save();

    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });

    res.status(201).json({
      token,
      user: {
        id: user._id,
        email: user.email,
        username: user.username,
        role: user.role
      }
    });
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });

    res.json({
      token,
      user: {
        id: user._id,
        email: user.email,
        username: user.username,
        role: user.role
      }
    });
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Change password - authenticated user
router.post('/change-password', authenticateToken, async (req, res) => {
  try {
    const { email, oldPassword, newPassword, confirmPassword } = req.body;
    
    if (!email || !oldPassword || !newPassword || !confirmPassword) {
      return res.status(400).json({ message: 'All fields are required' });
    }

    if (newPassword !== confirmPassword) {
      return res.status(400).json({ message: 'New passwords do not match' });
    }

    if (newPassword.length < 6) {
      return res.status(400).json({ message: 'Password must be at least 6 characters' });
    }

    if (oldPassword === newPassword) {
      return res.status(400).json({ message: 'New password must be different from old password' });
    }

    // Find user by email (case-insensitive)
    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) {
      console.log(`[PASSWORD CHANGE] User not found with email: ${email}`);
      return res.status(404).json({ message: 'User not found' });
    }

    console.log(`[PASSWORD CHANGE] Found user: ${user.username} (${user.email})`);

    // Verify old password
    const isMatch = await user.comparePassword(oldPassword);
    console.log(`[PASSWORD CHANGE] Password match result: ${isMatch}`);
    
    if (!isMatch) {
      console.log(`[PASSWORD CHANGE] Password verification failed for user: ${user.email}`);
      return res.status(401).json({ message: 'Current password is incorrect' });
    }

    // Update password
    user.password = newPassword;
    await user.save();

    // Log password change for security audit
    console.log(`[PASSWORD CHANGE] SUCCESS - User: ${user.username} (Email: ${user.email}, ID: ${user._id}) - Changed at ${new Date().toISOString()}`);

    res.status(200).json({ 
      message: 'Password changed successfully',
      user: {
        id: user._id,
        username: user.username,
        email: user.email
      }
    });
  } catch (error) {
    console.error('Change password error:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

export default router;
