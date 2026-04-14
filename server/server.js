import express from 'express';
import mongoose from 'mongoose';
import cors from 'cors';
import dotenv from 'dotenv';
import authRoutes from './routes/auth.js';
import productRoutes from './routes/products.js';
import wishlistRoutes from './routes/wishlist.js';
import orderRoutes from './routes/orders.js';
import contactRoutes from './routes/contact.js';
import paymentRoutes from './routes/payment.js';
import deliveryRequestRoutes from './routes/deliveryRequests.js';
import usersRoutes from './routes/users.js';
import bankRoutes from './routes/bank.js';
import { connectRedis } from './utils/redis.js';

dotenv.config();

const app = express();

app.use(cors());
app.use(express.json());

mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('MongoDB connection error:', err));

connectRedis();

// Register delivery-requests BEFORE orders to avoid route conflicts
app.use('/api/delivery-requests', deliveryRequestRoutes);
app.use('/api/auth', authRoutes);
app.use('/api/users', usersRoutes);
app.use('/api/bank', bankRoutes);
app.use('/api/products', productRoutes);
app.use('/api/wishlist', wishlistRoutes);
app.use('/api/orders', orderRoutes);
app.use('/api/contact', contactRoutes);
app.use('/api/payments', paymentRoutes);

app.get('/api/health', (req, res) => {
  res.json({ status: 'ok' });
});

// Global error handler
app.use((err, req, res, next) => {
  console.error('🔴 Global error handler:', err);
  res.status(500).json({ 
    message: 'Server error', 
    error: err.message,
    stack: process.env.NODE_ENV === 'development' ? err.stack : undefined
  });
});

// 404 handler
app.use((req, res) => {
  console.warn('⚠️ 404 Not Found:', req.method, req.path);
  res.status(404).json({ message: 'Route not found', path: req.path });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
