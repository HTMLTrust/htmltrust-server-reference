const mongoose = require('mongoose');

const ClaimSchema = new mongoose.Schema({
  name: {
    type: String,
    required: [true, 'Claim name is required'],
    unique: true,
    trim: true
  },
  description: {
    type: String,
    required: [true, 'Claim description is required'],
    trim: true
  },
  possibleValues: {
    type: [String],
    default: []
  },
  createdAt: {
    type: Date,
    default: Date.now
  },
  updatedAt: {
    type: Date,
    default: Date.now
  }
});

// Update the updatedAt field on save
ClaimSchema.pre('save', function(next) {
  this.updatedAt = Date.now();
  next();
});

module.exports = mongoose.model('Claim', ClaimSchema);