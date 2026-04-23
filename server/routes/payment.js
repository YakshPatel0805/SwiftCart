import express from "express";
import Order from "../models/Order.js";
import Payment from "../models/Payment.js";
import Bank from "../models/Bank.js";
import Product from "../models/Product.js";
import User from "../models/User.js";
import { authenticateToken } from "../middleware/auth.js";
import { isAdmin } from "../middleware/adminAuth.js";
import { sendPaymentConfirmationEmail, sendOrderConfirmationEmail, sendRefundConfirmationEmail } from "../utils/emailServices.js";

const router = express.Router();

// Shared helper: build order items from cart items
const buildOrderItems = async (items) => {
  const orderItems = [];
  for (const item of items) {
    const product = await Product.findById(item.productId);
    if (!product) throw { status: 400, message: `Product not found: ${item.productId}` };
    orderItems.push({
      product: item.productId,
      productSnapshot: { name: product.name, price: product.price, image: product.image },
      quantity: item.quantity
    });
  }
  return orderItems;
};

// Shared helper: create payment record and mark order processing
const finalizePayment = async (order, method) => {
  // Update existing pending payment or create new one
  let payment = await Payment.findOne({ orderId: order._id });
  
  if (payment) {
    // Update existing pending payment
    payment.method = method;
    payment.status = 'success';
    payment.transactionId = 'TXN' + Date.now();
    await payment.save();
  } else {
    // Create new payment (fallback for orders created without pending payment)
    payment = await Payment.create({
      orderId: order._id,
      userId: order.userId,
      amount: order.total,
      method,
      status: 'success',
      transactionId: 'TXN' + Date.now()
    });
  }
  
  // Send payment confirmation emails
  const user = await User.findById(order.userId);
  if (user) {
    sendPaymentConfirmationEmail(user, payment, order); // To User
    sendPaymentConfirmationEmail(user, payment, order, true); // To Admin
  }

  return payment;
};

// Get payment by order ID
router.get('/order/:orderId', authenticateToken, async (req, res) => {
  try {
    const payment = await Payment.findOne({ orderId: req.params.orderId });
    if (!payment) {
      return res.status(404).json({ message: 'Payment not found' });
    }
    res.json(payment);
  } catch (error) {
    console.error('Error fetching payment:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Handle cash on delivery payment (mark as success when delivered)
router.post("/cashondelivery", authenticateToken, async (req, res) => {
  try {
    const { orderId } = req.body;

    const order = await Order.findById(orderId);
    if (!order) return res.status(404).json({ message: "Order not found" });
    if (order.userId.toString() !== req.user.userId) return res.status(403).json({ message: "Not authorized for this order" });

    // Update or create payment record for cash on delivery
    let payment = await Payment.findOne({ orderId });
    
    if (payment) {
      payment.method = "cash-on-delivery";
      payment.status = "success";
      payment.transactionId = "COD" + Date.now();
      await payment.save();
    } else {
      payment = await Payment.create({
        orderId: order._id,
        userId: order.userId,
        amount: order.total,
        method: "cash-on-delivery",
        status: "success",
        transactionId: "COD" + Date.now()
      });
    }

    res.json({ message: "Cash on delivery payment recorded", payment });
  } catch (error) {
    console.error("Cash on delivery error:", error);
    res.status(error.status || 500).json({ message: error.message || "Server error" });
  }
});

// Pay for an existing order via bank account transfer
router.post("/accounttransfer", authenticateToken, async (req, res) => {
  try {
    const { orderId, accountNumber, pin } = req.body;

    const bankAccount = await Bank.findOne({
      userId: req.user.userId,
      "bankAccount.accountNumber": String(accountNumber),
      "bankAccount.accountPIN": String(pin),
    });
    if (!bankAccount) return res.status(401).json({ message: "Invalid account number or PIN" });

    const order = await Order.findById(orderId);
    if (!order) return res.status(404).json({ message: "Order not found" });
    if (order.userId.toString() !== req.user.userId) return res.status(403).json({ message: "Not authorized for this order" });
    if (bankAccount.bankAccount.balance < order.total) return res.status(400).json({ message: "Insufficient balance" });

    bankAccount.bankAccount.balance -= order.total;
    await bankAccount.save();

    const payment = await finalizePayment(order, "Account-Transfer");
    res.json({ message: "Payment successful", payment, remainingBalance: bankAccount.bankAccount.balance });
  } catch (error) {
    console.error("Payment error:", error);
    res.status(error.status || 500).json({ message: error.message || "Server error" });
  }
});

// Pay for an existing order via credit card
router.post("/creditcard", authenticateToken, async (req, res) => {
  try {
    const { orderId, cardNumber, cvv, expiry } = req.body;

    const bankAccount = await Bank.findOne({
      userId: req.user.userId,
      "creditCard.cardNumber": String(cardNumber),
      "creditCard.cardCVV": String(cvv),
      "creditCard.cardExpiry": expiry,
    });
    if (!bankAccount) return res.status(401).json({ message: "Invalid card details" });

    const order = await Order.findById(orderId);
    if (!order) return res.status(404).json({ message: "Order not found" });
    if (order.userId.toString() !== req.user.userId) return res.status(403).json({ message: "Not authorized for this order" });
    if (bankAccount.creditCard.cardBalance < order.total) return res.status(400).json({ message: "Insufficient card balance" });

    bankAccount.creditCard.cardBalance -= order.total;
    await bankAccount.save();

    const payment = await finalizePayment(order, "credit-card");
    res.json({ message: "Payment successful", payment, remainingBalance: bankAccount.creditCard.cardBalance });
  } catch (error) {
    console.error("Credit card payment error:", error);
    res.status(error.status || 500).json({ message: error.message || "Server error" });
  }
});

// Pay for an existing order via Google Pay
router.post("/googlepay", authenticateToken, async (req, res) => {
  try {
    const { orderId, accountId } = req.body;

    const bankAccount = await Bank.findOne({ _id: accountId, userId: req.user.userId });
    if (!bankAccount || !bankAccount.googlePay?.upiId) return res.status(401).json({ message: "Invalid Google Pay account" });

    const order = await Order.findById(orderId);
    if (!order) return res.status(404).json({ message: "Order not found" });
    if (order.userId.toString() !== req.user.userId) return res.status(403).json({ message: "Not authorized for this order" });
    if (bankAccount.googlePay.balance < order.total) return res.status(400).json({ message: "Insufficient Google Pay balance" });

    bankAccount.googlePay.balance -= order.total;
    await bankAccount.save();

    const payment = await finalizePayment(order, "google-pay");
    res.json({ message: "Payment successful", payment, remainingBalance: bankAccount.googlePay.balance });
  } catch (error) {
    console.error("Google Pay error:", error);
    res.status(error.status || 500).json({ message: error.message || "Server error" });
  }
});

// Create order + pay in one step via bank account transfer
router.post("/create-with-account-transfer", authenticateToken, async (req, res) => {
  try {
    const { items, total, shippingAddress, paymentMethod, accountNumber, pin } = req.body;

    const bankAccount = await Bank.findOne({
      userId: req.user.userId,
      "bankAccount.accountNumber": String(accountNumber),
      "bankAccount.accountPIN": String(pin),
    });
    if (!bankAccount) return res.status(401).json({ message: "Invalid account number or PIN" });
    if (bankAccount.bankAccount.balance < total) return res.status(400).json({ message: "Insufficient balance" });

    const orderItems = await buildOrderItems(items);
    bankAccount.bankAccount.balance -= total;
    await bankAccount.save();

    const order = await Order.create({ userId: req.user.userId, items: orderItems, total, shippingAddress, paymentMethod, status: "pending" });
    const payment = await finalizePayment(order, "Account-Transfer");

    res.status(201).json({ message: "Order placed successfully", order, payment, remainingBalance: bankAccount.bankAccount.balance });
  } catch (error) {
    console.error("Create with account transfer error:", error);
    res.status(error.status || 500).json({ message: error.message || "Server error" });
  }
});

// Create order + pay in one step via credit card
router.post("/create-with-credit-card", authenticateToken, async (req, res) => {
  try {
    const { items, total, shippingAddress, paymentMethod, cardNumber, cvv, expiry } = req.body;

    const bankAccount = await Bank.findOne({
      userId: req.user.userId,
      "creditCard.cardNumber": String(cardNumber),
      "creditCard.cardCVV": String(cvv),
      "creditCard.cardExpiry": expiry,
    });
    if (!bankAccount) return res.status(401).json({ message: "Invalid card details" });
    if (bankAccount.creditCard.cardBalance < total) return res.status(400).json({ message: "Insufficient card balance" });

    const orderItems = await buildOrderItems(items);
    bankAccount.creditCard.cardBalance -= total;
    await bankAccount.save();

    const order = await Order.create({ userId: req.user.userId, items: orderItems, total, shippingAddress, paymentMethod, status: "pending" });
    const payment = await finalizePayment(order, "credit-card");

    res.status(201).json({ message: "Order placed successfully", order, payment, remainingBalance: bankAccount.creditCard.cardBalance });
  } catch (error) {
    console.error("Create with credit card error:", error);
    res.status(error.status || 500).json({ message: error.message || "Server error" });
  }
});

// Create order + pay in one step via Google Pay
router.post("/create-with-googlepay", authenticateToken, async (req, res) => {
  try {
    const { items, total, shippingAddress, paymentMethod, accountId } = req.body;

    const bankAccount = await Bank.findOne({ _id: accountId, userId: req.user.userId });
    if (!bankAccount || !bankAccount.googlePay?.upiId) return res.status(401).json({ message: "Invalid Google Pay account" });
    if (bankAccount.googlePay.balance < total) return res.status(400).json({ message: "Insufficient Google Pay balance" });

    const orderItems = await buildOrderItems(items);
    bankAccount.googlePay.balance -= total;
    await bankAccount.save();

    const order = await Order.create({ userId: req.user.userId, items: orderItems, total, shippingAddress, paymentMethod, status: "pending" });
    const payment = await finalizePayment(order, "google-pay");

    res.status(201).json({ message: "Order placed successfully", order, payment, remainingBalance: bankAccount.googlePay.balance });
  } catch (error) {
    console.error("Create with Google Pay error:", error);
    res.status(error.status || 500).json({ message: error.message || "Server error" });
  }
});

// Admin endpoint to process refunds
router.post("/refund/:orderId", authenticateToken, isAdmin, async (req, res) => {
  try {
    const { orderId } = req.params;

    const order = await Order.findById(orderId);
    if (!order) return res.status(404).json({ message: "Order not found" });

    const payment = await Payment.findOne({ orderId, status: "success" });
    if (!payment) return res.status(400).json({ message: "No successful payment found for this order" });

    const bankAccount = await Bank.findOne({ userId: order.userId });
    if (!bankAccount) return res.status(404).json({ message: "User's bank account not found" });

    // Refund based on payment method
    let balanceUpdated = false;
    if (payment.method === "Account-Transfer") {
      bankAccount.bankAccount.balance += payment.amount;
      balanceUpdated = true;
    } else if (payment.method === "credit-card") {
      bankAccount.creditCard.cardBalance += payment.amount;
      balanceUpdated = true;
    } else if (payment.method === "google-pay") {
      bankAccount.googlePay.balance += payment.amount;
      balanceUpdated = true;
    } else if (payment.method === "cash-on-delivery") {
      return res.status(400).json({ message: "Cash on delivery orders cannot be refunded via bank transfer" });
    }

    if (balanceUpdated) {
      await bankAccount.save();
    }

    // Update payment status
    payment.status = "refunded";
    await payment.save();

    // Update order status
    order.status = "refunded";
    await order.save();

    // Restore stock
    for (const item of order.items) {
      const product = await Product.findById(item.product);
      if (product) {
        const restoredQty = (product.stockQuantity || 0) + item.quantity;
        await Product.findByIdAndUpdate(item.product, {
          stockQuantity: restoredQty,
          inStock: restoredQty > 0
        });
      }
    }

    // Send email to user
    const user = await User.findById(order.userId);
    if (user) {
      sendRefundConfirmationEmail(user, payment, order);
    }

    res.json({ message: "Refund processed successfully", payment, order });
  } catch (error) {
    console.error("Refund error:", error);
    res.status(500).json({ message: "Server error", error: error.message });
  }
});

export default router;

