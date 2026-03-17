import User from '../models/User.js';

export const isDeliveryBoy = async (req, res, next) => {
  try {
    if (!req.user || !req.user.userId) {
      return res.status(401).json({ message: 'User not authenticated' });
    }

    const user = await User.findById(req.user.userId);
    
    if (!user || user.role !== 'deliveryboy') {
      return res.status(403).json({ message: 'Access denied. Delivery boy role required.' });
    }
    
    // Add role to req.user for later use
    req.user.role = user.role;
    next();
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
};
