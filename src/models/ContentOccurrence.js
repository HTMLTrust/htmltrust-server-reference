const mongoose = require('mongoose');

const ContentOccurrenceSchema = new mongoose.Schema({
  signatureId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'ContentSignature',
    required: true
  },
  url: {
    type: String,
    required: [true, 'URL is required'],
    match: [
      /https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*)/,
      'Please use a valid URL'
    ]
  },
  domain: {
    type: String,
    required: [true, 'Domain is required'],
    index: true
  },
  firstSeen: {
    type: Date,
    default: Date.now
  },
  lastSeen: {
    type: Date,
    default: Date.now
  },
  signatureValid: {
    type: Boolean,
    default: true
  },
  reports: {
    type: Number,
    default: 0
  }
});

// Compound index for faster lookups
ContentOccurrenceSchema.index({ signatureId: 1, url: 1 }, { unique: true });

module.exports = mongoose.model('ContentOccurrence', ContentOccurrenceSchema);