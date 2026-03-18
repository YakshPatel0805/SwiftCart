import express from 'express';
import DeliveryRequest from '../models/DeliveryRequest.js';
import Order from '../models/Order.js';
import User from '../models/User.js';
import { authenticateToken } from '../middleware/auth.js';
import { isAdmin } from '../middleware/adminAuth.js';
import { isDeliveryBoy } from '../middleware/deliveryBoyAuth.js';
import { sendDeliveryRequestEmail } from '../utils/emailService.js';

const router = express.Router();

// Admin route - Send delivery requests to all delivery boys
router.post('/send/:orderId', authenticateToken, isAdmin, async (req, res) => {
  try {
    console.log('📨 Delivery Request: Received send request for order:', req.params.orderId);
    
    const { orderId } = req.params;

    // Check if order exists
    const order = await Order.findById(orderId);
    if (!order) {
      console.log('❌ Order not found:', orderId);
      return res.status(404).json({ message: 'Order not found' });
    }
    console.log('✓ Order found:', order._id);

    // Check if order already has an assigned delivery boy
    if (order.assignedDeliveryBoyId) {
      console.log('❌ Order already assigned to:', order.assignedDeliveryBoyId);
      return res.status(400).json({ message: 'Order already assigned to a delivery boy' });
    }

    // Get all delivery boys
    const deliveryBoys = await User.find({ role: 'deliveryboy' });
    console.log('✓ Found delivery boys:', deliveryBoys.length);
    
    if (deliveryBoys.length === 0) {
      console.log('❌ No delivery boys available');
      return res.status(400).json({ message: 'No delivery boys available' });
    }

    // Create delivery requests for each delivery boy
    const requests = await Promise.all(
      deliveryBoys.map(deliveryBoy =>
        DeliveryRequest.create({
          orderId,
          deliveryBoyId: deliveryBoy._id,
          status: 'pending'
        })
      )
    );
    console.log('✓ Created delivery requests:', requests.length);

    // Send email notifications to all delivery boys
    for (const deliveryBoy of deliveryBoys) {
      try {
        await sendDeliveryRequestEmail(order, deliveryBoy.email, deliveryBoy.username);
        console.log('✓ Email sent to:', deliveryBoy.email);
      } catch (emailError) {
        console.error('⚠️ Email error for', deliveryBoy.email, ':', emailError.message);
      }
    }

    console.log('✓ Delivery requests sent successfully');
    res.json({
      message: `Delivery requests sent to ${deliveryBoys.length} delivery boys`,
      requestCount: requests.length
    });
  } catch (error) {
    console.error('❌ Error sending delivery requests:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Admin route - Get delivery requests for an order (must be before /:requestId routes)
router.get('/order/:orderId', authenticateToken, isAdmin, async (req, res) => {
  try {
    const { orderId } = req.params;

    const requests = await DeliveryRequest.find({ orderId })
      .populate('deliveryBoyId', 'username email')
      .sort({ requestedAt: -1 });

    res.json(requests);
  } catch (error) {
    console.error('Error fetching delivery requests:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Delivery boy route - Get pending delivery requests
router.get('/pending', authenticateToken, isDeliveryBoy, async (req, res) => {
  try {
    console.log('📋 Fetching pending requests for delivery boy:', req.user.userId);
    
    const requests = await DeliveryRequest.find({
      deliveryBoyId: req.user.userId,
      status: 'pending'
    })
      .populate('orderId')
      .sort({ requestedAt: -1 });

    console.log('✓ Found pending requests:', requests.length);
    res.json(requests);
  } catch (error) {
    console.error('❌ Error fetching delivery requests:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Delivery boy route - Get all delivery requests (pending, accepted, rejected)
router.get('/', authenticateToken, isDeliveryBoy, async (req, res) => {
  try {
    const requests = await DeliveryRequest.find({
      deliveryBoyId: req.user.userId
    })
      .populate('orderId')
      .sort({ requestedAt: -1 });

    res.json(requests);
  } catch (error) {
    console.error('Error fetching delivery requests:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Delivery boy route - Accept delivery request
router.patch('/:requestId/accept', authenticateToken, isDeliveryBoy, async (req, res) => {
  try {
    const { requestId } = req.params;

    const request = await DeliveryRequest.findById(requestId);
    if (!request) {
      return res.status(404).json({ message: 'Delivery request not found' });
    }

    if (request.deliveryBoyId.toString() !== req.user.userId) {
      return res.status(403).json({ message: 'Unauthorized' });
    }

    if (request.status !== 'pending') {
      return res.status(400).json({ message: 'Request is no longer pending' });
    }

    // Check if order is already assigned
    const order = await Order.findById(request.orderId).populate('userId', 'username email mobile');
    if (order.assignedDeliveryBoyId) {
      // Another delivery boy already accepted
      request.status = 'rejected';
      request.respondedAt = new Date();
      await request.save();
      return res.status(400).json({ message: 'Order already assigned to another delivery boy' });
    }

    // Get delivery boy details
    const deliveryBoy = await User.findById(req.user.userId);

    // Accept the request
    request.status = 'accepted';
    request.respondedAt = new Date();
    await request.save();

    // Assign delivery boy to order
    order.assignedDeliveryBoyId = req.user.userId;
    await order.save();

    // Reject all other pending requests for this order
    await DeliveryRequest.updateMany(
      {
        orderId: request.orderId,
        _id: { $ne: requestId },
        status: 'pending'
      },
      {
        status: 'rejected',
        respondedAt: new Date()
      }
    );

    // Return comprehensive data for frontend
    res.json({
      message: 'Delivery request accepted',
      request: await request.populate('orderId'),
      // Delivery boy details to send to user
      deliveryBoyDetails: {
        name: deliveryBoy.username,
        email: deliveryBoy.email,
        mobile: deliveryBoy.mobile
      },
      // User and delivery details to send to delivery boy
      userAndDeliveryDetails: {
        customerName: order.shippingAddress.name,
        customerMobile: order.userId.mobile,
        customerEmail: order.userId.email,
        deliveryAddress: {
          address: order.shippingAddress.address,
          city: order.shippingAddress.city,
          state: order.shippingAddress.state,
          zipcode: order.shippingAddress.zipcode,
          country: order.shippingAddress.country
        }
      }
    });
  } catch (error) {
    console.error('Error accepting delivery request:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Delivery boy route - Reject delivery request
router.patch('/:requestId/reject', authenticateToken, isDeliveryBoy, async (req, res) => {
  try {
    const { requestId } = req.params;

    const request = await DeliveryRequest.findById(requestId);
    if (!request) {
      return res.status(404).json({ message: 'Delivery request not found' });
    }

    if (request.deliveryBoyId.toString() !== req.user.userId) {
      return res.status(403).json({ message: 'Unauthorized' });
    }

    if (request.status !== 'pending') {
      return res.status(400).json({ message: 'Request is no longer pending' });
    }

    request.status = 'rejected';
    request.respondedAt = new Date();
    await request.save();

    res.json({
      message: 'Delivery request rejected',
      request
    });
  } catch (error) {
    console.error('Error rejecting delivery request:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

export default router;
