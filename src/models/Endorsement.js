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
 * The structured endorsement document is stored in `document`. Older clients
 * may still send or read `contentHash`/`rawBlob`, but the draft field name for
 * the targeted content hash is `endorsement`.
 */
const EndorsementSchema = new mongoose.Schema({
  // Opaque endorser keyid (e.g. "did:web:publisher.org" or any other form
  // resolvable to a public key per spec §2.3).
  endorser: {
    type: String,
    required: [true, 'Endorser keyid is required'],
    index: true
  },
  // Draft field: targeted content hash, e.g. "sha256:..." per spec §6.2.
  endorsement: {
    type: String,
    required: [true, 'Endorsement content hash is required'],
    index: true
  },
  // Legacy alias retained for current clients and existing data.
  contentHash: {
    type: String,
    required: [true, 'Content hash is required'],
    index: true
  },
  // Base64-encoded signature over JCS(document with signature omitted).
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
    enum: [
      'ed25519',
      'ED25519',
      'RSA',
      'ECDSA',
      'rsa-pkcs1-sha256',
      'rsa-pss-sha256',
      'ecdsa-p256',
      'ecdsa-p384'
    ],
    default: 'ed25519'
  },
  claim: String,
  expires: String,
  revokedBy: String,
  // The endorsement document exactly as it was submitted and verified. It is
  // served back verbatim: draft §10.1 requires unrecognised members to be
  // preserved and included in the signed payload, so adding, renaming, or
  // dropping a member here would invalidate the endorser's signature.
  document: {
    type: mongoose.Schema.Types.Mixed,
    required: [true, 'Structured endorsement document is required']
  },
  // sha256 of JCS(document), used as the identity of the stored document.
  documentHash: {
    type: String,
    required: [true, 'Document hash is required'],
    unique: true,
    index: true
  },
  // Legacy signed blob field retained for compatibility only.
  rawBlob: {
    type: String
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

// Endorsements are append-only. An endorser may have several documents on
// file for the same content hash — draft §10.3 requires a directory holding
// both an endorsement and its revocation to serve BOTH, so that verifiers can
// observe the revocation chain. Deduplication is by document identity
// (`documentHash`), which makes resubmitting the identical document
// idempotent while keeping distinct documents distinct.
//
// MIGRATION: databases created before this change carry unique indexes on
// { contentHash, endorser } and { endorsement, endorser }. Those indexes
// silently collapse a revocation onto the endorsement it revokes and must be
// dropped:
//   db.endorsements.dropIndex("contentHash_1_endorser_1")
//   db.endorsements.dropIndex("endorsement_1_endorser_1")
EndorsementSchema.index({ contentHash: 1, endorser: 1 });
EndorsementSchema.index({ endorsement: 1, endorser: 1 });

EndorsementSchema.pre('validate', function(next) {
  if (!this.endorsement && this.contentHash) this.endorsement = this.contentHash;
  if (!this.contentHash && this.endorsement) this.contentHash = this.endorsement;
  next();
});

module.exports = mongoose.model('Endorsement', EndorsementSchema);
