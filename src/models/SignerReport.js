const mongoose = require('mongoose');

/** One authenticated report about an exact signer keyid. */
const SignerReportSchema = new mongoose.Schema({
  reportId: { type: String, required: true, unique: true, immutable: true },
  reporterId: { type: String, required: true, maxlength: 2048 },
  signerId: { type: String, required: true, maxlength: 2048 },
  requestKey: { type: String, required: true, maxlength: 128 },
  reason: {
    type: String,
    enum: ['IMPERSONATION', 'MISINFORMATION', 'SPAM', 'OTHER'],
    required: true,
  },
  details: { type: String, maxlength: 4096 },
  evidence: { type: String, maxlength: 2048 },
  status: {
    type: String,
    enum: ['PENDING', 'UNDER_REVIEW', 'ACCEPTED', 'REJECTED'],
    default: 'PENDING',
  },
}, { timestamps: true });

SignerReportSchema.index(
  { reporterId: 1, signerId: 1, requestKey: 1 },
  { unique: true },
);
SignerReportSchema.index({ signerId: 1 });

module.exports = mongoose.model('SignerReport', SignerReportSchema);
