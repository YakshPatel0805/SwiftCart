import mongoose from 'mongoose';

const orderSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  items: [{
    product: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Product'
    },
    productSnapshot: {
      name: String,
      price: Number,
      image: String
    },
    quantity: {
      type: Number,
      required: true
    }
  }],
  total: {
    type: Number,
    required: true
  },
  status: {
    type: String,
    enum: ['pending', 'processing', 'shipped', 'delivered', 'cancelled'],
    default: 'pending'
  },
  shippingAddress: {
    name: String,
    email: String,
    address: String,
    city: String,
    state: String,
    zipcode: String,
    country: String
  },
  paymentMethod: {
    type: {
      type: String,
      enum: ['credit-card', 'google-pay', 'cash-on-delivery', 'Account-Transfer']
    },
    cardholderName: String
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

export default mongoose.model('Order', orderSchema);
