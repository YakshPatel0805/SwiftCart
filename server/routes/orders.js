import express from 'express';
import Order from '../models/Order.js';
import DeliveryRequest from '../models/DeliveryRequest.js';
import Product from '../models/Product.js';
import User from '../models/User.js';
import Payment from '../models/Payment.js';
import { authenticateToken } from '../middleware/auth.js';
import { isAdmin } from '../middleware/adminAuth.js';
import { isDeliveryBoy } from '../middleware/deliveryBoyAuth.js';
import {
  sendOrderConfirmationEmail,
  sendNewOrderAdminEmail,
  sendOrderCancellationEmail,
  sendOrderDeliveredEmail
} from '../utils/emailServices.js';

const router = express.Router();

// Admin route - Get all orders
router.get('/admin/all', authenticateToken, isAdmin, async (req, res) => {
  try {
    const orders = await Order.find()
      .populate('items.product')
      .populate('userId', 'email username')
      .populate('assignedDeliveryBoyId', 'username email mobile')
      .sort({ createdAt: -1 });
    
    // Fetch payment data for each order
    const ordersWithPayment = await Promise.all(
      orders.map(async (order) => {
        const payment = await Payment.findOne({ orderId: order._id });
        return {
          ...order.toObject(),
          payment
        };
      })
    );
    
    res.json(ordersWithPayment);
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// User route - Get user's own orders
router.get('/', authenticateToken, async (req, res) => {
  try {
    const orders = await Order.find({ userId: req.user.userId })
      .populate('items.product')
      .populate('assignedDeliveryBoyId', 'username email mobile')
      .sort({ createdAt: -1 });
    
    // Fetch payment data for each order
    const ordersWithPayment = await Promise.all(
      orders.map(async (order) => {
        const payment = await Payment.findOne({ orderId: order._id });
        return {
          ...order.toObject(),
          payment
        };
      })
    );
    
    res.json(ordersWithPayment);
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
      paymentMethod: paymentMethod,
      status: 'pending'
    });

    await order.save();
    console.log('Order saved successfully:', order._id);

    // Create a pending payment record for this order
    try {
      const paymentMethodData = req.body.paymentMethod;
      let methodType = 'unknown';
      
      // Handle both object and string formats
      if (typeof paymentMethodData === 'object' && paymentMethodData?.type) {
        methodType = paymentMethodData.type;
      } else if (typeof paymentMethodData === 'string') {
        methodType = paymentMethodData;
      }
      
      const payment = await Payment.create({
        orderId: order._id,
        userId: req.user.userId,
        amount: order.total,
        method: methodType,
        status: 'pending',
        transactionId: null
      });
      console.log('Pending payment record created:', payment._id);
    } catch (paymentError) {
      console.error('Error creating pending payment:', paymentError);
      // Don't fail the order creation if payment record fails
    }

    // Auto-update stock for each product
    for (const item of orderItems) {
      const product = await Product.findById(item.product);
      if (product) {
        const newQty = Math.max(0, (product.stockQuantity || 0) - item.quantity);
        await Product.findByIdAndUpdate(item.product, {
          stockQuantity: newQty,
          inStock: newQty > 0
        });
        console.log(`Updated stock for product ${product.name}: ${newQty} remaining`);
      } else {
        console.warn(`Product not found for stock update: ${item.product}`);
      }
    }

    await order.populate('items.product');

    sendNewOrderAdminEmail(order);

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

    // Use findByIdAndUpdate to avoid validation issues with old payment methods
    const updatedOrder = await Order.findByIdAndUpdate(
      req.params.id,
      { status: 'cancelled' },
      { new: true, runValidators: false }
    ).populate('items.product');

    // Restore stock for each cancelled item
    for (const item of order.items) {
      const product = await Product.findById(item.product);
      if (product) {
        const restoredQty = (product.stockQuantity || 0) + item.quantity;
        await Product.findByIdAndUpdate(item.product, {
          stockQuantity: restoredQty,
          inStock: restoredQty > 0
        });
        console.log(`Restored stock for ${product.name}: ${restoredQty}`);
      }
    }
    // Send cancellation emails
    const user = await User.findById(req.user.userId);
    if (user) {
      sendOrderCancellationEmail(user, updatedOrder); // To User
      sendOrderCancellationEmail(user, updatedOrder, true); // To Admin
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

    const update = { status };

    const order = await Order.findById(req.params.id);
    if (!order) {
      return res.status(404).json({ message: 'Order not found' });
    }

    const previousStatus = order.status;
    const updatedOrder = await Order.findByIdAndUpdate(
      req.params.id,
      update,
      { new: true, runValidators: false }
    ).populate('items.product').populate('userId', 'email username');

    // Handle stock restoration if cancelled by admin
    if (status === 'cancelled' && previousStatus !== 'cancelled') {
      for (const item of updatedOrder.items) {
        // Use item.product._id because it's populated
        const productId = item.product._id || item.product;
        const product = await Product.findById(productId);
        if (product) {
          const restoredQty = (product.stockQuantity || 0) + item.quantity;
          await Product.findByIdAndUpdate(productId, {
            stockQuantity: restoredQty,
            inStock: restoredQty > 0
          });
        }
      }
    }

    // Handle soldCount increment if delivered
    if (status === 'delivered' && previousStatus !== 'delivered') {
      for (const item of updatedOrder.items) {
        const productId = item.product._id || item.product;
        await Product.findByIdAndUpdate(productId, {
          $inc: { soldCount: item.quantity }
        });
      }

      // If order is delivered and payment method is Cash on Delivery, update payment status to success
      if (updatedOrder.paymentMethod && updatedOrder.paymentMethod.type === 'cash-on-delivery') {
        await Payment.findOneAndUpdate(
          { orderId: req.params.id },
          { 
            status: 'success',
            transactionId: 'COD' + Date.now()
          }
        );
      }
    }


    res.json(updatedOrder);
  } catch (error) {
    console.error('Error updating order status:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Track order - Get order with delivery boy details
router.get('/:id/track', authenticateToken, async (req, res) => {
  try {
    const order = await Order.findOne({
      _id: req.params.id,
      userId: req.user.userId
    })
      .populate('items.product')
      .populate('assignedDeliveryBoyId', 'username email mobile');

    if (!order) {
      return res.status(404).json({ message: 'Order not found' });
    }

    // Fetch payment data
    const payment = await Payment.findOne({ orderId: order._id });

    // Get delivery boy contact info if assigned
    let deliveryBoyInfo = null;
    if (order.assignedDeliveryBoyId) {
      deliveryBoyInfo = {
        name: order.assignedDeliveryBoyId.username,
        email: order.assignedDeliveryBoyId.email,
        mobile: order.assignedDeliveryBoyId.mobile
      };
    }

    const getStatusHistory = (order) => {
      const history = [
        { status: 'pending', date: order.createdAt, description: 'Order placed successfully' }
      ];

      if (order.status === 'processing' || order.status === 'shipped' || order.status === 'delivered') {
        history.push({
          status: 'processing',
          date: new Date(new Date(order.createdAt).getTime() + 30 * 60000), // 30 minutes later
          description: 'Order confirmed and being prepared'
        });
      }

      if (order.status === 'shipped' || order.status === 'delivered') {
        history.push({
          status: 'shipped',
          date: new Date(new Date(order.createdAt).getTime() + 24 * 60 * 60000), // 1 day later
          description: 'Order shipped and on the way'
        });
      }

      if (order.status === 'delivered') {
        history.push({
          status: 'delivered',
          date: new Date(new Date(order.createdAt).getTime() + 72 * 60 * 60000), // 3 days later
          description: 'Order delivered successfully'
        });
      }

      if (order.status === 'cancelled') {
        history.push({
          status: 'cancelled',
          date: new Date(),
          description: 'Order cancelled'
        });
      }

      return history;
    };

    const trackingInfo = {
      orderId: order._id,
      status: order.status,
      createdAt: order.createdAt,
      items: order.items,
      total: order.total,
      shippingAddress: order.shippingAddress,
      payment,
      deliveryBoy: deliveryBoyInfo,
      statusHistory: getStatusHistory(order)
    };

    res.json(trackingInfo);
  } catch (error) {
    console.error('Error tracking order:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Delivery Boy routes - Get all orders for delivery
router.get('/deliveryboy/all', authenticateToken, isDeliveryBoy, async (req, res) => {
  try {
    // Get only orders assigned to this delivery boy
    const orders = await Order.find({ assignedDeliveryBoyId: req.user.userId })
      .populate('items.product')
      .populate('userId', 'email username')
      .sort({ createdAt: -1 });

    // Fetch payment data for each order
    const ordersWithPayment = await Promise.all(
      orders.map(async (order) => {
        const payment = await Payment.findOne({ orderId: order._id });
        return {
          ...order.toObject(),
          payment
        };
      })
    );

    res.json(ordersWithPayment);
  } catch (error) {
    console.error('❌ Error fetching delivery boy orders:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Delivery Boy route - Update order status (only pending and delivered)
router.patch('/deliveryboy/:id/status', authenticateToken, isDeliveryBoy, async (req, res) => {
  try {
    const { status } = req.body;

    if (!status) {
      return res.status(400).json({ message: 'Status is required' });
    }

    // Delivery boys can only change to 'shipped' or 'delivered'
    const allowedStatuses = ['shipped', 'delivered'];
    if (!allowedStatuses.includes(status)) {
      return res.status(400).json({ message: 'Delivery boys can only update to shipped or delivered status' });
    }

    const order = await Order.findById(req.params.id);
    if (!order) {
      return res.status(404).json({ message: 'Order not found' });
    }

    // Check if this delivery boy is assigned to this order
    if (order.assignedDeliveryBoyId.toString() !== req.user.userId) {
      return res.status(403).json({ message: 'You are not assigned to this order' });
    }

    // Can only update orders that are in processing or shipped status
    if (order.status !== 'processing' && order.status !== 'shipped') {
      return res.status(400).json({ message: 'Can only update orders in processing or shipped status' });
    }

    const updatedOrder = await Order.findByIdAndUpdate(
      req.params.id,
      { status },
      { new: true, runValidators: false }
    ).populate('items.product').populate('userId', 'email username');

    // If order is delivered, mark delivery request as completed, increment soldCount and send emails
    if (status === 'delivered') {
      await DeliveryRequest.updateOne(
        { orderId: req.params.id, deliveryBoyId: req.user.userId },
        { status: 'completed', completedAt: new Date() }
      );

      // Increment soldCount for each product in the order
      for (const item of updatedOrder.items) {
        const productId = item.product._id || item.product;
        await Product.findByIdAndUpdate(productId, {
          $inc: { soldCount: item.quantity }
        });
      }


      // If order is delivered and payment method is Cash on Delivery, update payment status to success
      if (updatedOrder.paymentMethod && updatedOrder.paymentMethod.type === 'cash-on-delivery') {
        await Payment.findOneAndUpdate(
          { orderId: req.params.id },
          { 
            status: 'success',
            transactionId: 'COD' + Date.now()
          }
        );
      }
    }

    res.json(updatedOrder);
  } catch (error) {
    console.error('Error updating order status:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});
// Admin route - Get recent important updates (pending, cancelled, delivered) for notifications
router.get('/admin/notifications/recent', authenticateToken, isAdmin, async (req, res) => {
  try {
    console.log('--- NOTIFICATION POLL START ---');
    const recentUpdates = await Order.find({
      status: { $in: ['pending', 'cancelled', 'delivered'] }
    })
      .populate('userId', 'username email')
      .sort({ updatedAt: -1 })
      .limit(10);
    
    console.log(`--- NOTIFICATION POLL END: Found ${recentUpdates.length} orders ---`);
    res.json(recentUpdates);
  } catch (error) {
    console.error('--- NOTIFICATION POLL ERROR ---', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Admin route - Get total order count (for dashboards)
router.get('/admin/stats/count', authenticateToken, isAdmin, async (req, res) => {
  try {
    const count = await Order.countDocuments();
    res.json({ count });
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

export default router;
