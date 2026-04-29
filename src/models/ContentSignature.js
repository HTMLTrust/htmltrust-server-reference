const mongoose = require('mongoose');

const ContentSignatureSchema = new mongoose.Schema({
  contentHash: {
    type: String,
    required: [true, 'Content hash is required'],
    index: true
  },
  // Canonical hash of the claims map (sorted, newline-joined "name=value"
  // serialization, then hashed). Part of the signature binding per spec §2.1.
  claimsHash: {
    type: String,
    default: ''
  },
  // ISO-8601 timestamp from the <meta name="signed-at"> element in the
  // signed-section. Part of the signature binding per spec §2.1.
  signedAt: {
    type: String,
    default: ''
  },
  domain: {
    type: String,
    required: [true, 'Domain is required'],
    index: true
  },
  authorId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Author',
    required: true,
    index: true
  },
  keyId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Key',
    required: true
  },
  signature: {
    type: String,
    required: [true, 'Signature is required']
  },
  claims: {
    type: Map,
    of: String,
    default: {}
  },
  createdAt: {
    type: Date,
    default: Date.now
  },
  occurrences: {
    type: Number,
    default: 1
  }
});

// Compound index for faster lookups
ContentSignatureSchema.index({ contentHash: 1, domain: 1, authorId: 1 }, { unique: true });

// Virtual for content occurrences
ContentSignatureSchema.virtual('contentOccurrences', {
  ref: 'ContentOccurrence',
  localField: '_id',
  foreignField: 'signatureId',
  justOne: false
});

module.exports = mongoose.model('ContentSignature', ContentSignatureSchema);