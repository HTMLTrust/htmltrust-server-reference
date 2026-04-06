const mongoose = require('mongoose');

const AuthorSchema = new mongoose.Schema({
  name: {
    type: String,
    required: [true, 'Please add a name'],
    trim: true
  },
  description: {
    type: String,
    trim: true
  },
  url: {
    type: String,
    match: [
      /https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*)/,
      'Please use a valid URL'
    ]
  },
  keyType: {
    type: String,
    enum: ['HUMAN', 'AI', 'HUMAN_AI_MIX', 'ORGANIZATION'],
    required: [true, 'Please specify the key type']
  },
  apiKey: {
    type: String,
    select: false // Don't return API key in queries
  },
  createdAt: {
    type: Date,
    default: Date.now
  },
  updatedAt: {
    type: Date,
    default: Date.now
  }
}, {
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

// Virtual for keys
AuthorSchema.virtual('keys', {
  ref: 'Key',
  localField: '_id',
  foreignField: 'authorId',
  justOne: false
});

// Virtual for content signatures
AuthorSchema.virtual('signatures', {
  ref: 'ContentSignature',
  localField: '_id',
  foreignField: 'authorId',
  justOne: false
});

// Update the updatedAt field on save
AuthorSchema.pre('save', function(next) {
  this.updatedAt = Date.now();
  next();
});

module.exports = mongoose.model('Author', AuthorSchema);