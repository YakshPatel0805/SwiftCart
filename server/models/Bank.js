import mongoose from "mongoose";

const BankSchema = new mongoose.Schema({
  bankDetails: {
    bankName: { type: String, required: true },
    IFSCCode: { type: String, required: true },
  },
});

export default mongoose.model("Bank", BankSchema);