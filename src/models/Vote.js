const mongoose = require('mongoose');

const VoteSchema = new mongoose.Schema({
  userId: {
    type: String,
    required: [true, 'User ID is required'],
    index: true
  },
  targetType: {
    type: String,
    enum: ['AUTHOR', 'CONTENT'],
    required: [true, 'Target type is required']
  },
  targetId: {
    type: mongoose.Schema.Types.ObjectId,
    required: [true, 'Target ID is required'],
    refPath: 'targetType',
    index: true
  },
  voteType: {
    type: String,
    enum: ['TRUST', 'DISTRUST'],
    required: [true, 'Vote type is required']
  },
  reason: {
    type: String
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

// Compound index to ensure a user can only vote once per target
VoteSchema.index({ userId: 1, targetType: 1, targetId: 1 }, { unique: true });

// Update the updatedAt field on save
VoteSchema.pre('save', function(next) {
  this.updatedAt = Date.now();
  next();
});

module.exports = mongoose.model('Vote', VoteSchema);