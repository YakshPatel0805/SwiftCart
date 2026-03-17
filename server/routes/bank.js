import express from 'express';
import Bank from '../models/Bank.js';
import { authenticateToken } from '../middleware/auth.js';

const router = express.Router();

// Get all accounts for a user
router.get('/', authenticateToken, async (req, res) => {
  try {
    const doc = await Bank.findOne({ userId: req.user.userId });
    const accounts = doc ? doc.accounts : [];
    res.json(accounts);
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Get single account by entry _id
router.get('/:accountId', authenticateToken, async (req, res) => {
  try {
    const doc = await Bank.findOne({ userId: req.user.userId });
    const account = doc?.accounts.id(req.params.accountId);
    if (!account) return res.status(404).json({ message: 'Account not found' });
    res.json(account);
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Add account — pushes into existing user doc or creates one
router.post('/', authenticateToken, async (req, res) => {
  try {
    const { accountType, bankAccount, creditCard, googlePay, isDefault } = req.body;

    const validTypes = ['bank-account', 'credit-card', 'google-pay'];
    if (!validTypes.includes(accountType)) {
      return res.status(400).json({ message: 'Invalid account type' });
    }

    if (accountType === 'bank-account' && (!bankAccount?.accountNumber || !bankAccount?.accountPIN)) {
      return res.status(400).json({ message: 'Bank account requires accountNumber and accountPIN' });
    }
    if (accountType === 'credit-card' && (!creditCard?.cardNumber || !creditCard?.cardCVV || !creditCard?.cardExpiry)) {
      return res.status(400).json({ message: 'Credit card requires cardNumber, cardCVV, and cardExpiry' });
    }
    if (accountType === 'google-pay' && !googlePay?.upiId) {
      return res.status(400).json({ message: 'Google Pay requires upiId' });
    }

    // Check for duplicate account/card number across all users
    if (bankAccount?.accountNumber) {
      const exists = await Bank.findOne({ 'accounts.bankAccount.accountNumber': bankAccount.accountNumber });
      if (exists) return res.status(400).json({ message: 'Account number already registered' });
    }
    if (creditCard?.cardNumber) {
      const exists = await Bank.findOne({ 'accounts.creditCard.cardNumber': creditCard.cardNumber });
      if (exists) return res.status(400).json({ message: 'Card number already registered' });
    }

    const newEntry = {
      accountType,
      bankAccount: accountType === 'bank-account' ? bankAccount : undefined,
      creditCard: accountType === 'credit-card' ? creditCard : undefined,
      googlePay: accountType === 'google-pay' ? googlePay : undefined,
      isDefault: isDefault || false
    };

    const doc = await Bank.findOneAndUpdate(
      { userId: req.user.userId },
      { $push: { accounts: newEntry } },
      { new: true, upsert: true }
    );

    const added = doc.accounts[doc.accounts.length - 1];
    res.status(201).json({ message: 'Account added successfully', account: added });
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Update an account entry
router.patch('/:accountId', authenticateToken, async (req, res) => {
  try {
    const { bankAccount, creditCard, googlePay, isDefault } = req.body;
    const doc = await Bank.findOne({ userId: req.user.userId });
    if (!doc) return res.status(404).json({ message: 'No accounts found' });

    const account = doc.accounts.id(req.params.accountId);
    if (!account) return res.status(404).json({ message: 'Account not found' });

    if (bankAccount) Object.assign(account.bankAccount, bankAccount);
    if (creditCard) Object.assign(account.creditCard, creditCard);
    if (googlePay) Object.assign(account.googlePay, googlePay);
    if (isDefault !== undefined) account.isDefault = isDefault;

    await doc.save();
    res.json({ message: 'Account updated successfully', account });
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Delete an account entry
router.delete('/:accountId', authenticateToken, async (req, res) => {
  try {
    const doc = await Bank.findOneAndUpdate(
      { userId: req.user.userId },
      { $pull: { accounts: { _id: req.params.accountId } } },
      { new: true }
    );
    if (!doc) return res.status(404).json({ message: 'Account not found' });
    res.json({ message: 'Account deleted successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Set default account
router.patch('/:accountId/set-default', authenticateToken, async (req, res) => {
  try {
    const doc = await Bank.findOne({ userId: req.user.userId });
    if (!doc) return res.status(404).json({ message: 'No accounts found' });

    doc.accounts.forEach(a => { a.isDefault = a._id.toString() === req.params.accountId; });
    await doc.save();

    res.json({ message: 'Default account updated' });
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

export default router;
