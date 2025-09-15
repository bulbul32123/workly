import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';

const RefreshTokenSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  tokenHash: { type: String, required: true },
  expiresAt: { type: Date, required: true },
  createdAt: { type: Date, default: Date.now },
  replacedByToken: { type: String, default: null },
  revoked: { type: Boolean, default: false }
});

RefreshTokenSchema.methods.matches = async function (plain) {
  return bcrypt.compare(plain, this.tokenHash);
};

export default mongoose.models.RefreshToken || mongoose.model('RefreshToken', RefreshTokenSchema);
