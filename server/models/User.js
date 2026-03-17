import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';

const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  username: { type: String, required: true, unique: true, trim: true },
  password: { type: String, required: true },
  role: { type: String, enum: ['user', 'admin', 'deliveryboy'], default: 'user' },
  wishlist: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Product' }],
  accountDetails: {
    accountHolderName: { type: String },
    accountNumber: { type: String, unique: true, sparse: true },
    accountPIN : { type: String },
    balance: { type: Number, default: 0 },
  },
  creditCardDetails : {
    cardHolderName: { type: String },
    cardNumber : { type: String, unique: true, sparse: true },
    cardCVV : { type: String },
    cardExpiry : { type: String },
    cardBalance : { type: Number, default: 0 },
  },
  createdAt: { type: Date, default: Date.now }
});

userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  this.password = await bcrypt.hash(this.password, 10);
  next();
});

userSchema.methods.comparePassword = async function(candidatePassword) {
  return await bcrypt.compare(candidatePassword, this.password);
};

export default mongoose.model('User', userSchema);
