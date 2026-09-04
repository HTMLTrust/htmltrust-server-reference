const mongoose = require('mongoose');

/** One authenticated voter's current opinion about one signer keyid. */
const SignerVoteSchema = new mongoose.Schema({
  voterId: { type: String, required: true, trim: true, maxlength: 2048 },
  signerId: { type: String, required: true, trim: true, maxlength: 2048 },
  voteType: { type: String, enum: ['TRUST', 'DISTRUST'], required: true },
  reason: { type: String, maxlength: 4096 },
}, { timestamps: true });

SignerVoteSchema.index({ voterId: 1, signerId: 1 }, { unique: true });
SignerVoteSchema.index({ signerId: 1 });

module.exports = mongoose.model('SignerVote', SignerVoteSchema);
