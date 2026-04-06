const mongoose = require('mongoose');

const KeySchema = new mongoose.Schema({
  authorId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Author',
    required: true
  },
  publicKey: {
    type: String,
    required: [true, 'Public key is required']
  },
  privateKey: {
    type: String,
    required: [true, 'Private key is required'],
    select: false // Don't return private key in queries
  },
  algorithm: {
    type: String,
    enum: ['RSA', 'ECDSA', 'ED25519'],
    default: 'RSA',
    required: true
  },
  createdAt: {
    type: Date,
    default: Date.now
  },
  expiresAt: {
    type: Date
  },
  trustScore: {
    type: Number,
    min: 0,
    max: 1,
    default: 0.5
  },
  verifiedSignatures: {
    type: Number,
    default: 0
  },
  reports: {
    type: Number,
    default: 0
  }
});

// Virtual for content signatures
KeySchema.virtual('signatures', {
  ref: 'ContentSignature',
  localField: '_id',
  foreignField: 'keyId',
  justOne: false
});

module.exports = mongoose.model('Key', KeySchema);