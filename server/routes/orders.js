import express from 'express';
import Order from '../models/Order.js';
import Product from '../models/Product.js';
import User from '../models/User.js';
import { authenticateToken } from '../middleware/auth.js';
import { isAdmin } from '../middleware/adminAuth.js';
import { 
  sendOrderConfirmationEmail, 
  sendOrderCancellationEmail, 
  sendPaymentConfirmationEmail,
  sendAdminOrderNotification,
  sendAdminCancellationNotification
} from '../utils/emailService.js';

const router = express.Router();

// Admin route - Get all orders
router.get('/admin/all', authenticateToken, isAdmin, async (req, res) => {
  try {
    const orders = await Order.find()
      .populate('items.product')
      .populate('userId', 'email username')
      .sort({ createdAt: -1 });
    res.json(orders);
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// User route - Get user's own orders
router.get('/', authenticateToken, async (req, res) => {
  try {
    const orders = await Order.find({ userId: req.user.userId })
      .populate('items.product')
      .sort({ createdAt: -1 });
    res.json(orders);
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

router.get('/:id', authenticateToken, async (req, res) => {
  try {
    const order = await Order.findOne({ 
      _id: req.params.id, 
      userId: req.user.userId 
    }).populate('items.product');
    
    if (!order) {
      return res.status(404).json({ message: 'Order not found' });
    }
    
    res.json(order);
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

router.post('/', authenticateToken, async (req, res) => {
  try {
    console.log('Creating order for user:', req.user.userId);
    console.log('Order data received:', req.body);
    
    const { items, total, shippingAddress, paymentMethod } = req.body;

    if (!items || items.length === 0) {
      return res.status(400).json({ message: 'No items in order' });
    }

    // Get user details for email
    const user = await User.findById(req.user.userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    const orderItems = await Promise.all(
      items.map(async (item) => {
        console.log('Processing item:', item);
        const product = await Product.findById(item.productId);
        
        if (!product) {
          console.error('Product not found:', item.productId);
          throw new Error(`Product not found: ${item.productId}`);
        }
        
        return {
          product: item.productId,
          productSnapshot: {
            name: product.name,
            price: product.price,
            image: product.image
          },
          quantity: item.quantity
        };
      })
    );

    const order = new Order({
      userId: req.user.userId,
      items: orderItems,
      total,
      shippingAddress,
      paymentMethod: paymentMethod
    });

    await order.save();
    console.log('Order saved successfully:', order._id);
    
    await order.populate('items.product');
    
    // Send order confirmation email
    const emailSent = await sendOrderConfirmationEmail(order, shippingAddress.email || user.email);
    if (emailSent) {
      console.log('Order confirmation email sent successfully');
    }
    
    // Send payment confirmation email (for immediate payment methods)
    if (paymentMethod.type === 'credit-card' || paymentMethod.type === 'google-pay' || paymentMethod.type === 'Account-Transfer') {
      const paymentEmailSent = await sendPaymentConfirmationEmail(order, shippingAddress.email || user.email);
      if (paymentEmailSent) {
        console.log('Payment confirmation email sent successfully');
      }
    }
    
    // Send admin notification about new order
    const adminNotificationSent = await sendAdminOrderNotification(
      order, 
      shippingAddress.email || user.email,
      shippingAddress.name || user.username
    );
    if (adminNotificationSent) {
      console.log('Admin order notification sent successfully');
    }
    
    res.status(201).json(order);
  } catch (error) {
    console.error('Error creating order:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Cancel order endpoint
router.patch('/:id/cancel', authenticateToken, async (req, res) => {
  try {
    const order = await Order.findOne({ 
      _id: req.params.id, 
      userId: req.user.userId 
    });
    
    if (!order) {
      return res.status(404).json({ message: 'Order not found' });
    }
    
    // Only allow cancellation if order is not shipped or delivered
    if (order.status === 'delivered') {
      return res.status(400).json({ message: 'Cannot cancel order that is already shipped or delivered' });
    }
    
    // Get user details for email
    const user = await User.findById(req.user.userId);
    
    // Use findByIdAndUpdate to avoid validation issues with old payment methods
    const updatedOrder = await Order.findByIdAndUpdate(
      req.params.id,
      { status: 'cancelled' },
      { new: true, runValidators: false }
    ).populate('items.product');
    
    // Send order cancellation email
    if (user) {
      const emailSent = await sendOrderCancellationEmail(updatedOrder, order.shippingAddress.email || user.email);
      if (emailSent) {
        console.log('Order cancellation email sent successfully');
      }
      
      // Send admin notification about order cancellation
      const adminNotificationSent = await sendAdminCancellationNotification(
        updatedOrder,
        order.shippingAddress.email || user.email,
        order.shippingAddress.name || user.username
      );
      if (adminNotificationSent) {
        console.log('Admin cancellation notification sent successfully');
      }
    }
    
    res.json(updatedOrder);
  } catch (error) {
    console.error('Error cancelling order:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Admin route - Update order status
router.patch('/:id/status', authenticateToken, isAdmin, async (req, res) => {
  try {
    const { status } = req.body;
    
    if (!status) {
      return res.status(400).json({ message: 'Status is required' });
    }
    
    const validStatuses = ['pending', 'processing', 'shipped', 'delivered', 'cancelled'];
    if (!validStatuses.includes(status)) {
      return res.status(400).json({ message: 'Invalid status' });
    }
    
    const updatedOrder = await Order.findByIdAndUpdate(
      req.params.id,
      { status },
      { new: true, runValidators: false }
    ).populate('items.product').populate('userId', 'email username');
    
    if (!updatedOrder) {
      return res.status(404).json({ message: 'Order not found' });
    }
    
    res.json(updatedOrder);
  } catch (error) {
    console.error('Error updating order status:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

export default router;
