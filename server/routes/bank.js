import express from 'express';
import Bank from '../models/Bank.js';
import User from '../models/User.js';
import { authenticateToken } from '../middleware/auth.js';

const router = express.Router();

// Get all accounts for a user - returns array format for frontend compatibility
router.get('/', authenticateToken, async (req, res) => {
  try {
    const doc = await Bank.findOne({ userId: req.user.userId });
    if (!doc) return res.json([]);

    const accounts = [];
    
    // Convert flat structure to array format for frontend
    if (doc.bankAccount?.accountHolderName) {
      accounts.push({
        _id: 'bank-account',
        bankAccount: doc.bankAccount,
        isDefault: doc.bankAccount.isDefault,
        createdAt: doc.createdAt
      });
    }
    
    if (doc.creditCard?.cardHolderName) {
      accounts.push({
        _id: 'credit-card',
        creditCard: doc.creditCard,
        isDefault: doc.creditCard.isDefault,
        createdAt: doc.createdAt
      });
    }
    
    if (doc.googlePay?.upiId) {
      accounts.push({
        _id: 'google-pay',
        googlePay: doc.googlePay,
        isDefault: doc.googlePay.isDefault,
        createdAt: doc.createdAt
      });
    }

    res.json(accounts);
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Add/Update account - upserts the document and updates specific account type
router.post('/', authenticateToken, async (req, res) => {
  try {
    const { bankAccount, creditCard, googlePay, isDefault } = req.body;

    if (!bankAccount && !creditCard && !googlePay) {
      return res.status(400).json({ message: 'Provide bankAccount, creditCard, or googlePay data' });
    }

    // Validation
    if (bankAccount && (!bankAccount.accountNumber || !bankAccount.accountPIN)) {
      return res.status(400).json({ message: 'Bank account requires accountNumber and accountPIN' });
    }
    if (creditCard && (!creditCard.cardNumber || !creditCard.cardCVV || !creditCard.cardExpiry)) {
      return res.status(400).json({ message: 'Credit card requires cardNumber, cardCVV, and cardExpiry' });
    }
    if (googlePay && !googlePay.upiId) {
      return res.status(400).json({ message: 'Google Pay requires upiId' });
    }

    // Check for duplicates across all users
    if (bankAccount?.accountNumber) {
      const exists = await Bank.findOne({ 'bankAccount.accountNumber': bankAccount.accountNumber });
      if (exists && exists.userId.toString() !== req.user.userId) {
        return res.status(400).json({ message: 'Account number already registered' });
      }
    }
    if (creditCard?.cardNumber) {
      const exists = await Bank.findOne({ 'creditCard.cardNumber': creditCard.cardNumber });
      if (exists && exists.userId.toString() !== req.user.userId) {
        return res.status(400).json({ message: 'Card number already registered' });
      }
    }

    // Get username from User model
    const user = await User.findById(req.user.userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    const updateData = {};

    // Include username in the update
    updateData.username = user.username;
    
    if (bankAccount) {
      updateData.bankAccount = { ...bankAccount, isDefault: isDefault || false };
    }
    if (creditCard) {
      updateData.creditCard = { ...creditCard, isDefault: isDefault || false };
    }
    if (googlePay) {
      updateData.googlePay = { ...googlePay, isDefault: isDefault || false };
    }


    const doc = await Bank.findOneAndUpdate(
      { userId: req.user.userId },
      { $set: updateData },
      { new: true, upsert: true }
    );

    res.status(201).json({ message: 'Account added/updated successfully', account: doc });
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Delete specific account type
router.delete('/:accountType', authenticateToken, async (req, res) => {
  try {
    const { accountType } = req.params;
    const validTypes = ['bank-account', 'credit-card', 'google-pay'];
    
    if (!validTypes.includes(accountType)) {
      return res.status(400).json({ message: 'Invalid account type' });
    }

    const fieldName = accountType === 'bank-account' ? 'bankAccount' : 
                     accountType === 'credit-card' ? 'creditCard' : 'googlePay';

    const doc = await Bank.findOneAndUpdate(
      { userId: req.user.userId },
      { $unset: { [fieldName]: 1 } },
      { new: true }
    );

    if (!doc) return res.status(404).json({ message: 'Account not found' });
    res.json({ message: 'Account deleted successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Set default account
router.patch('/:accountType/set-default', authenticateToken, async (req, res) => {
  try {
    const { accountType } = req.params;
    const validTypes = ['bank-account', 'credit-card', 'google-pay'];
    
    if (!validTypes.includes(accountType)) {
      return res.status(400).json({ message: 'Invalid account type' });
    }

    const doc = await Bank.findOne({ userId: req.user.userId });
    if (!doc) return res.status(404).json({ message: 'No accounts found' });

    // Reset all defaults
    if (doc.bankAccount) doc.bankAccount.isDefault = false;
    if (doc.creditCard) doc.creditCard.isDefault = false;
    if (doc.googlePay) doc.googlePay.isDefault = false;

    // Set the requested one as default
    const fieldName = accountType === 'bank-account' ? 'bankAccount' : 
                     accountType === 'credit-card' ? 'creditCard' : 'googlePay';
    
    if (doc[fieldName]) {
      doc[fieldName].isDefault = true;
    }

    await doc.save();
    res.json({ message: 'Default account updated' });
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

export default router;