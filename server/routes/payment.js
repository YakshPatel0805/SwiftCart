import express from "express";
import Order from "../models/Order.js";
import Payment from "../models/Payment.js";
import { authenticateToken } from "../middleware/auth.js";

const router = express.Router();

router.post("/accounttransfer", authenticateToken, async (req, res) => {
  try {
    const { orderId, accountNumber, pin, IFSCCode } = req.body;

    const order = await Order.findById(orderId);
    if (!order) return res.status(404).json({ message: "Order not found" });

    if (order.status !== "pending") {
      return res.status(400).json({ message: "Order already paid or processed" });
    }

    const bankUser = await Bank.findOne({
      "userDetails.accountNumber": String(accountNumber),
      "userDetails.accountPIN": pin,
    });

    if (!bankUser) {
      return res.status(401).json({ message: "Invalid account number or PIN" });
    }

    if (bankUser.userDetails.balance < order.total) {
      return res.status(400).json({ message: "Insufficient balance" });
    }

    bankUser.userDetails.balance -= order.total;
    await bankUser.save();

    const payment = await Payment.create({
      orderId: order._id,
      userId: order.userId,
      amount: order.total,
      method: "Account Transfer",
      status: "success",
      transactionId: "TXN" + Date.now()
    });

    order.status = "processing";
    await order.save();

    res.json({
      message: "Payment successful",
      payment,
      remainingBalance: bankUser.userDetails.balance
    });

  } catch (error) {
    console.error("Payment error:", error);
    res.status(500).json({ message: "Server error", error: error.message });
  }
});

export default router;