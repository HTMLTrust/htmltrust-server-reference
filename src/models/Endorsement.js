const mongoose = require('mongoose');

/**
 * Endorsement model.
 *
 * Per HTMLTrust spec §2.5, an endorsement is a standalone signed JSON blob
 * issued by a third party (publisher, expert, other user) that attests an
 * opinion about a specific piece of signed content at a specific moment in
 * time. Endorsements target specific content hashes, not signers.
 *
 * The directory acts as a passive store: it indexes endorsements by content
 * hash and serves them on request. Cryptographic verification of an
 * endorsement is performed locally by the verifier using the endorser's
 * public key (resolved via the same keyid mechanisms as content signatures).
 *
 * The original signed JSON blob is stored verbatim in `rawBlob` so verifiers
 * can re-verify byte-identically without re-serializing — any change to the
 * key order or whitespace would invalidate the signature.
 */
const EndorsementSchema = new mongoose.Schema({
  // Opaque endorser keyid (e.g. "did:web:publisher.org" or any other form
  // resolvable to a public key per spec §2.3).
  endorser: {
    type: String,
    required: [true, 'Endorser keyid is required'],
    index: true
  },
  // The targeted content hash, e.g. "sha256:..." per spec §2.1.
  contentHash: {
    type: String,
    required: [true, 'Content hash is required'],
    index: true
  },
  // Base64-encoded signature over the binding "{contentHash}:{timestamp}".
  signature: {
    type: String,
    required: [true, 'Signature is required']
  },
  // ISO-8601 timestamp at which the endorsement was issued.
  timestamp: {
    type: String,
    required: [true, 'Timestamp is required']
  },
  algorithm: {
    type: String,
    enum: ['ed25519', 'ED25519', 'RSA', 'ECDSA'],
    default: 'ed25519'
  },
  // Original signed JSON blob the client posted, stored verbatim so verifiers
  // can re-verify byte-identically without re-serializing.
  rawBlob: {
    type: String,
    required: [true, 'rawBlob is required']
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

// Dedupe: a given endorser may only have one endorsement on file per content
// hash. Resubmissions update the existing record (see controller).
EndorsementSchema.index({ contentHash: 1, endorser: 1 }, { unique: true });

module.exports = mongoose.model('Endorsement', EndorsementSchema);
