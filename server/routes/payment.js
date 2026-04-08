import express from "express";
import Order from "../models/Order.js";
import Payment from "../models/Payment.js";
import Bank from "../models/Bank.js";
import Product from "../models/Product.js";
import User from "../models/User.js";
import { authenticateToken } from "../middleware/auth.js";
import { sendPaymentConfirmationEmail, sendOrderConfirmationEmail } from "../utils/mail.js";

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
  const payment = await Payment.create({
    orderId: order._id,
    userId: order.userId,
    amount: order.total,
    method,
    status: "success",
    transactionId: "TXN" + Date.now()
  });
  // Send payment confirmation emails
  const user = await User.findById(order.userId);
  if (user) {
    sendPaymentConfirmationEmail(user, payment, order); // To User
    sendPaymentConfirmationEmail(user, payment, order, true); // To Admin
  }

  return payment;
};

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

export default router;

