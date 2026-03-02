import express from "express";
import Order from "../models/Order.js";
import Payment from "../models/Payment.js";
import User from "../models/User.js";
import Product from "../models/Product.js";
import { authenticateToken } from "../middleware/auth.js";

const router = express.Router();

router.post("/accounttransfer", authenticateToken, async (req, res) => {
  try {
    const { orderId, accountNumber, pin } = req.body;

    const user = await User.findOne({
      "accountDetails.accountNumber": String(accountNumber),
      "accountDetails.accountPIN": pin,
    });

    if (!user) {
      return res.status(401).json({ message: "Invalid account number or PIN" });
    }

    // Get the order to check total
    const order = await Order.findById(orderId);
    if (!order) {
      return res.status(404).json({ message: "Order not found" });
    }

    // Check if order belongs to the current user
    if (order.userId.toString() !== req.user.userId) {
      return res.status(403).json({ message: "Not authorized for this order" });
    }

    if (user.accountDetails.balance < order.total) {
      return res.status(400).json({ message: "Insufficient balance" });
    }

    // Deduct balance
    user.accountDetails.balance -= order.total;
    await user.save();

    // Create payment record
    const payment = await Payment.create({
      orderId: order._id,
      userId: order.userId,
      amount: order.total,
      method: "Account-Transfer",
      status: "success",
      transactionId: "TXN" + Date.now()
    });

    // Update order status
    order.status = "processing";
    await order.save();

    res.json({
      message: "Payment successful",
      payment,
      remainingBalance: user.accountDetails.balance
    });

  } catch (error) {
    console.error("Payment error:", error);
    res.status(500).json({ message: "Server error", error: error.message });
  }
});

router.post("/creditcard", authenticateToken, async (req, res) => {
  try {
    const { orderId, cardNumber, cvv, expiry } = req.body;

    // First validate credit card
    const user = await User.findOne({
      "creditCardDetails.cardNumber": String(cardNumber),
      "creditCardDetails.cardCVV": cvv,
      "creditCardDetails.cardExpiry": expiry,
    });

    if (!user) {
      return res.status(401).json({ message: "Invalid card details" });
    }

    // Get the order to check total
    const order = await Order.findById(orderId);
    if (!order) {
      return res.status(404).json({ message: "Order not found" });
    }

    // Check if order belongs to the current user
    if (order.userId.toString() !== req.user.userId) {
      return res.status(403).json({ message: "Not authorized for this order" });
    }

    if (user.creditCardDetails.cardBalance < order.total) {
      return res.status(400).json({ message: "Insufficient card balance" });
    }

    // Deduct card balance
    user.creditCardDetails.cardBalance -= order.total;
    await user.save();

    // Create payment record
    const payment = await Payment.create({
      orderId: order._id,
      userId: order.userId,
      amount: order.total,
      method: "credit-card",
      status: "success",
      transactionId: "TXN" + Date.now()
    });

    // Update order status
    order.status = "processing";
    await order.save();

    res.json({
      message: "Payment successful",
      payment,
      remainingBalance: user.creditCardDetails.cardBalance
    });

  } catch (error) {
    console.error("Credit card payment error:", error);
    res.status(500).json({ message: "Server error", error: error.message });
  }
});

router.post("/create-with-account-transfer", authenticateToken, async (req, res) => {
  try {
    const { items, total, shippingAddress, paymentMethod, accountNumber, pin } = req.body;

    const user = await User.findOne({
      "accountDetails.accountNumber": String(accountNumber),
      "accountDetails.accountPIN": String(pin),
    });

    if (!user) {
      return res.status(401).json({ message: "Invalid account number or PIN" });
    }

    if (user.accountDetails.balance < total) {
      return res.status(400).json({ message: "Insufficient balance" });
    }

    // Validate all products exist
    const orderItems = [];
    for (const item of items) {
      const product = await Product.findById(item.productId);
      if (!product) {
        return res.status(400).json({ message: `Product not found: ${item.productId}` });
      }
      orderItems.push({
        product: item.productId,
        productSnapshot: {
          name: product.name,
          price: product.price,
          image: product.image
        },
        quantity: item.quantity
      });
    }

    // Deduct balance BEFORE creating order
    user.accountDetails.balance -= total;
    await user.save();

    // Create order
    const order = new Order({
      userId: req.user.userId,
      items: orderItems,
      total,
      shippingAddress,
      paymentMethod: paymentMethod,
      status: "processing"
    });

    await order.save();

    // Create payment record
    const payment = await Payment.create({
      orderId: order._id,
      userId: order.userId,
      amount: total,
      method: "Account-Transfer",
      status: "success",
      transactionId: "TXN" + Date.now()
    });

    res.status(201).json({
      message: "Order placed successfully",
      order,
      payment,
      remainingBalance: user.accountDetails.balance
    });

  } catch (error) {
    console.error("Create with account transfer error:", error);
    res.status(500).json({ message: "Server error", error: error.message });
  }
});

router.post("/create-with-credit-card", authenticateToken, async (req, res) => {
  try {
    const { items, total, shippingAddress, paymentMethod, cardNumber, cvv, expiry } = req.body;

    const user = await User.findOne({
      "creditCardDetails.cardNumber": String(cardNumber),
      "creditCardDetails.cardCVV": cvv,
      "creditCardDetails.cardExpiry": expiry,
    });

    if (!user) {
      return res.status(401).json({ message: "Invalid card details" });
    }

    if (user.creditCardDetails.cardBalance < total) {
      return res.status(400).json({ message: "Insufficient card balance" });
    }

    // Validate all products exist
    const orderItems = [];
    for (const item of items) {
      const product = await Product.findById(item.productId);
      if (!product) {
        return res.status(400).json({ message: `Product not found: ${item.productId}` });
      }
      orderItems.push({
        product: item.productId,
        productSnapshot: {
          name: product.name,
          price: product.price,
          image: product.image
        },
        quantity: item.quantity
      });
    }

    // Deduct card balance BEFORE creating order
    user.creditCardDetails.cardBalance -= total;
    await user.save();

    // Create order
    const order = new Order({
      userId: req.user.userId,
      items: orderItems,
      total,
      shippingAddress,
      paymentMethod: paymentMethod,
      status: "processing"
    });

    await order.save();

    // Create payment record
    const payment = await Payment.create({
      orderId: order._id,
      userId: order.userId,
      amount: total,
      method: "credit-card",
      status: "success",
      transactionId: "TXN" + Date.now()
    });

    res.status(201).json({
      message: "Order placed successfully",
      order,
      payment,
      remainingBalance: user.creditCardDetails.cardBalance
    });

  } catch (error) {
    console.error("Create with credit card error:", error);
    res.status(500).json({ message: "Server error", error: error.message });
  }
});

export default router;
