import express from 'express';
import User from '../models/User.js';
import { authenticateToken } from '../middleware/auth.js';
import { isAdmin } from '../middleware/adminAuth.js';

const router = express.Router();

// Get all users (admin only)
router.get('/', authenticateToken, isAdmin, async (req, res) => {
  try {
    console.log('📋 Fetching all users');
    
    const users = await User.find({}, '-password').sort({ createdAt: -1 });
    
    console.log(`✓ Found ${users.length} users`);
    res.json(users);
  } catch (error) {
    console.error('❌ Error fetching users:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Update user role (admin only)
router.patch('/:userId/role', authenticateToken, isAdmin, async (req, res) => {
  try {
    const { userId } = req.params;
    const { role } = req.body;

    // Validate role
    const validRoles = ['user', 'admin', 'deliveryboy'];
    if (!validRoles.includes(role)) {
      return res.status(400).json({ 
        message: 'Invalid role. Must be one of: user, admin, deliveryboy' 
      });
    }

    // Prevent admin from removing their own admin role
    if (userId === req.user.userId && role !== 'admin') {
      return res.status(400).json({ 
        message: 'Cannot remove your own admin role' 
      });
    }

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    const oldRole = user.role;
    user.role = role;
    await user.save();

    console.log(`✓ User role updated: ${user.username} (${oldRole} → ${role})`);

    res.json({
      message: 'User role updated successfully',
      user: {
        _id: user._id,
        email: user.email,
        username: user.username,
        role: user.role
      }
    });
  } catch (error) {
    console.error('❌ Error updating user role:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Get user by ID (admin only)
router.get('/:userId', authenticateToken, isAdmin, async (req, res) => {
  try {
    const { userId } = req.params;

    const user = await User.findById(userId, '-password');
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    res.json(user);
  } catch (error) {
    console.error('Error fetching user:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

export default router;
