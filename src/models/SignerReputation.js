const mongoose = require('mongoose');

/**
 * A directory may evaluate a signer that is published by another directory.
 * Keep that opinion separate from Key, which represents locally resolvable key
 * material and therefore requires a local author relationship.
 */
const SignerReputationSchema = new mongoose.Schema({
  signerId: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    maxlength: 2048,
  },
  trustScore: { type: Number, min: 0, max: 1, default: 0.5 },
  verifiedSignatures: { type: Number, min: 0, default: 0 },
  reports: { type: Number, min: 0, default: 0 },
}, { timestamps: true });

module.exports = mongoose.model('SignerReputation', SignerReputationSchema);
