const mongoose = require('mongoose');

const ContentSignatureSchema = new mongoose.Schema({
  contentHash: {
    type: String,
    required: [true, 'Content hash is required'],
    index: true
  },
  // Canonical hash of the complete direct-child claims array.
  claimsHash: {
    type: String,
    default: ''
  },
  // Exact v1 timestamp from the signed-at claim.
  signedAt: {
    type: String,
    default: ''
  },
  domain: {
    type: String,
    index: true
  },
  profile: {
    type: String,
    index: true
  },
  algorithm: String,
  keyid: {
    type: String,
    index: true
  },
  scope: String,
  location: {
    type: String,
    index: true
  },
  sourceURL: String,
  authorId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Author',
    index: true
  },
  keyId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Key'
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

// Pre-v1 rows and v1 rows have different identities. A v1 signature may be
// indexed at more than one signed URL, including when its key is remote and
// has no local Author row.
ContentSignatureSchema.index(
  { contentHash: 1, domain: 1, authorId: 1 },
  {
    unique: true,
    partialFilterExpression: {
      domain: { $type: 'string' },
      authorId: { $type: 'objectId' },
      // MongoDB partial indexes support `$in`, while `$exists: false` is not
      // a supported partial-index predicate. `null` matches the missing
      // profile field on pre-v1 documents and keeps v1 rows out of this
      // legacy identity index.
      profile: { $in: [null] }
    }
  }
);
ContentSignatureSchema.index(
  { contentHash: 1, profile: 1, location: 1, keyid: 1 },
  {
    unique: true,
    partialFilterExpression: { profile: 'htmltrust-signature-v1' }
  }
);

// Virtual for content occurrences
ContentSignatureSchema.virtual('contentOccurrences', {
  ref: 'ContentOccurrence',
  localField: '_id',
  foreignField: 'signatureId',
  justOne: false
});

module.exports = mongoose.model('ContentSignature', ContentSignatureSchema);
