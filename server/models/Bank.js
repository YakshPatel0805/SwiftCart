import mongoose from 'mongoose';

const bankSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    unique: true
  },
  username: {
    type: String,
    required: true
  },
  bankAccount: {
    accountHolderName: { type: String },
    accountNumber: { type: String },
    accountPIN: { type: String },
    balance: { type: Number, default: 0 },
    isDefault: { type: Boolean, default: false }
  },
  creditCard: {
    cardHolderName: { type: String },
    cardNumber: { type: String },
    cardCVV: { type: String },
    cardExpiry: { type: String },
    cardBalance: { type: Number, default: 0 },
    isDefault: { type: Boolean, default: false }
  },
  googlePay: {
    mobileNumber: { type: String },
    upiId: { type: String },
    PIN: { type: String },
    balance: { type: Number, default: 0 },
    isDefault: { type: Boolean, default: false }
  },
  createdAt: { type: Date, default: Date.now }
});

export default mongoose.model('Bank', bankSchema);