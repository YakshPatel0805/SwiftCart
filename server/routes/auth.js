import express from 'express';
import jwt from 'jsonwebtoken';
import User from '../models/User.js';
import { authenticateToken } from '../middleware/auth.js';

const router = express.Router();

router.post('/signup', async (req, res) => {
  try {
    const { email, username, password, mobile } = req.body;

    // Validate required fields
    if (!email || !username || !password || !mobile) {
      return res.status(400).json({ success: false, message: 'All fields including mobile number are required' });
    }

    // Validate mobile number format (basic validation)
    const mobileRegex = /^[\+]?[1-9][\d]{0,15}$/;
    if (!mobileRegex.test(mobile)) {
      return res.status(400).json({ success: false, message: 'Please enter a valid mobile number' });
    }

    const existingUser = await User.findOne({ $or: [{ email }, { username }] });
    if (existingUser) {
      return res.status(400).json({ success: false, message: 'Username or email already exists' });
    }

    // Check if mobile number already exists
    const existingMobile = await User.findOne({ mobile });
    if (existingMobile) {
      return res.status(400).json({ success: false, message: 'Mobile number already registered' });
    }

    const isAdminSignup = email === process.env.ADMIN_EMAIL && username === 'admin' && password === 'admin123';

    const user = new User({
      email,
      username,
      password,
      mobile,
      role: isAdminSignup ? 'admin' : 'user'
    });
    await user.save();

    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });

    res.status(201).json({
      success: true,
      token,
      user: {
        id: user._id,
        email: user.email,
        username: user.username,
        mobile: user.mobile,
        role: user.role
      }
    });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Server error', error: error.message });
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
        mobile: user.mobile,
        role: user.role
      }
    });
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

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

    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    const isMatch = await user.comparePassword(oldPassword);
    if (!isMatch) {
      return res.status(401).json({ message: 'Current password is incorrect' });
    }

    // FIX: Assign plain password — pre('save') hook will hash it correctly
    user.password = newPassword;
    await user.save();

    console.log(`[PASSWORD CHANGE] SUCCESS - User: ${user.username} at ${new Date().toISOString()}`);
    res.json({ message: 'Password changed successfully' });

  } catch (error) {
    console.error('Change password error:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

router.patch('/update-profile', authenticateToken, async (req, res) => {
  try {
    const { username, email, mobile } = req.body;

    if (!username || !email) {
      return res.status(400).json({ message: 'Username and email are required' });
    }

    // Validate mobile number if provided
    if (mobile) {
      const mobileRegex = /^[\+]?[1-9][\d]{0,15}$/;
      if (!mobileRegex.test(mobile)) {
        return res.status(400).json({ message: 'Please enter a valid mobile number' });
      }
    }

    const user = await User.findById(req.user.userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Check if email is already taken by another user
    const existingUser = await User.findOne({ 
      email: email.toLowerCase(),
      _id: { $ne: user._id }
    });
    if (existingUser) {
      return res.status(400).json({ message: 'Email already in use' });
    }

    // Check if username is already taken by another user
    const existingUsername = await User.findOne({ 
      username,
      _id: { $ne: user._id }
    });
    if (existingUsername) {
      return res.status(400).json({ message: 'Username already in use' });
    }

    // Check if mobile is already taken by another user (if provided)
    if (mobile) {
      const existingMobile = await User.findOne({ 
        mobile,
        _id: { $ne: user._id }
      });
      if (existingMobile) {
        return res.status(400).json({ message: 'Mobile number already in use' });
      }
    }

    user.username = username;
    user.email = email.toLowerCase();
    if (mobile) {
      user.mobile = mobile;
    }
    await user.save();

    res.json({
      message: 'Profile updated successfully',
      user: {
        id: user._id,
        email: user.email,
        username: user.username,
        mobile: user.mobile,
        role: user.role
      }
    });
  } catch (error) {
    console.error('Update profile error:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

export default router;