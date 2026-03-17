import { type } from '@testing-library/user-event/dist/cjs/utility/type.js';
import mongoose from 'mongoose';

const accountEntrySchema = new mongoose.Schema({
  accountType: {
    type: String,
    enum: ['bank-account', 'credit-card', 'google-pay'],
    required: true
  },
  bankAccount: {
    accountHolderName: { type: String },
    accountNumber: { type: String },
    accountPIN: { type: String },
    balance: { type: Number, default: 0 }
  },
  creditCard: {
    cardHolderName: { type: String },
    cardNumber: { type: String },
    cardCVV: { type: String },
    cardExpiry: { type: String },
    cardBalance: { type: Number, default: 0 }
  },
  googlePay: {
    mobileNumber: { type: String },
    upiId: { type: String },
    PIN: { type: String },
    balance: { type: Number, default: 0 }
  },
  isDefault: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now }
});

const bankSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    unique: true
  },
  accounts: [accountEntrySchema]
});

export default mongoose.model('Bank', bankSchema);
