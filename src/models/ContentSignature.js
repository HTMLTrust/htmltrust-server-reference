const mongoose = require('mongoose');

const ContentSignatureSchema = new mongoose.Schema({
  contentHash: {
    type: String,
    required: [true, 'Content hash is required'],
    index: true
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