import mongoose from "mongoose";

const paymentSchema = new mongoose.Schema({
  orderId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Order",
    required: true
  },

  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true
  },

  amount: {
    type: Number,
    required: true
  },

  method: {
    type: String,
    enum: ["Account-Transfer", "cash-on-delivery", 'google-pay', 'credit-card'],
    required: true
  },

  status: {
    type: String,
    enum: ["success", "failed"],
    required: true
  },

  transactionId: {
    type: String
  },

  createdAt: {
    type: Date,
    default: Date.now
  }
});

export default mongoose.model("Payment", paymentSchema);