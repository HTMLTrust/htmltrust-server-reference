const mongoose = require('mongoose');
const crypto = require('crypto');

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
  // Opaque public identifier used in directory key URLs. The Mongo `_id` is
  // storage metadata and must not be the protocol-facing key identifier.
  // `sparse` keeps existing pre-v1 rows resolvable during migration; legacy
  // rows without publicId continue to use their ObjectId as a compatibility
  // alias until they are rewritten.
  publicId: {
    type: String,
    // New keys always receive the default below. Legacy hydrated keys may
    // still omit or contain null here until migrate:v1 backfills them, so
    // updates to those rows must remain valid during the migration window.
    required: function publicIdRequired() {
      return this.isNew;
    },
    immutable: true,
    validate: {
      validator(value) {
        return !this.isNew || /^k_[A-Za-z0-9_-]{20,64}$/.test(value);
      },
      message: 'publicId must be an opaque k_ identifier',
    },
    unique: true,
    sparse: true,
    index: true,
    // Mongoose hydrates defaults onto legacy rows too. Only generate this
    // value for new documents, so an old row without publicId remains
    // addressable through its historical ObjectId compatibility alias.
    default: function generatePublicId() {
      return this.isNew ? `k_${crypto.randomBytes(18).toString('base64url')}` : undefined;
    },
  },
  // Only populated when the directory generated the key pair on the author's
  // behalf. Authors who register their own public key keep custody of the
  // private half and this field stays unset.
  privateKey: {
    type: String,
    select: false // Don't return private key in queries
  },
  algorithm: {
    type: String,
    enum: [
      'RSA',
      'ECDSA',
      'ED25519',
      'rsa-pkcs1-sha256',
      'rsa-pss-sha256',
      'ecdsa-p256',
      'ecdsa-p384',
      'ed25519'
    ],
    default: 'ed25519',
    required: true
  },
  createdAt: {
    type: Date,
    default: Date.now
  },
  expiresAt: {
    type: Date
  },
  // Draft §8.2: a revoked key MUST NOT be used to verify a signature, so
  // revocation is recorded here and enforced during key resolution.
  revoked: {
    type: Boolean,
    default: false
  },
  revokedAt: Date,
  supersededBy: String,
  previousKeys: {
    type: [String],
    default: undefined
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
