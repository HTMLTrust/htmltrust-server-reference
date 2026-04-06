const Key = require('../models/Key');
const Author = require('../models/Author');
const ContentSignature = require('../models/ContentSignature');
const ContentOccurrence = require('../models/ContentOccurrence');

/**
 * @desc    Search public keys
 * @route   GET /api/directory/keys
 * @access  Public
 */
exports.searchPublicKeys = async (req, res) => {
  try {
    const { authorName, keyType, domain, minTrustScore, page = 1, limit = 20 } = req.query;
    
    // Build query
    const query = {};
    
    // Join with Author model to filter by author name and key type
    const authorQuery = {};
    if (authorName) authorQuery.name = { $regex: authorName, $options: 'i' };
    if (keyType) authorQuery.keyType = keyType;
    
    // Filter by trust score
    if (minTrustScore) query.trustScore = { $gte: parseFloat(minTrustScore) };
    
    // Pagination
    const skip = (parseInt(page) - 1) * parseInt(limit);
    
    // Execute query with aggregation to join with Author model
    const keys = await Key.aggregate([
      {
        $lookup: {
          from: 'authors',
          localField: 'authorId',
          foreignField: '_id',
          as: 'author'
        }
      },
      {
        $unwind: '$author'
      },
      {
        $match: {
          ...query,
          'author': { $exists: true },
          ...Object.keys(authorQuery).length > 0 ? { 'author': authorQuery } : {}
        }
      },
      {
        $skip: skip
      },
      {
        $limit: parseInt(limit)
      },
      {
        $project: {
          _id: 1,
          authorId: 1,
          publicKey: 1,
          algorithm: 1,
          createdAt: 1,
          expiresAt: 1,
          trustScore: 1,
          verifiedSignatures: 1,
          reports: 1,
          author: 1
        }
      }
    ]);
    
    // Get total count
    const total = await Key.countDocuments(query);
    
    res.status(200).json({
      keys,
      pagination: {
        total,
        pages: Math.ceil(total / parseInt(limit)),
        page: parseInt(page),
        limit: parseInt(limit)
      }
    });
  } catch (error) {
    console.error('Search public keys error:', error);
    res.status(500).json({
      code: 'SERVER_ERROR',
      message: error.message
    });
  }
};

/**
 * @desc    Get key reputation
 * @route   GET /api/directory/keys/:keyId/reputation
 * @access  Public
 */
exports.getKeyReputation = async (req, res) => {
  try {
    const key = await Key.findById(req.params.keyId);
    
    if (!key) {
      return res.status(404).json({
        code: 'NOT_FOUND',
        message: 'Key not found'
      });
    }
    
    res.status(200).json({
      keyId: key._id,
      trustScore: key.trustScore,
      verifiedSignatures: key.verifiedSignatures,
      reports: key.reports,
      lastUpdated: key.updatedAt || key.createdAt
    });
  } catch (error) {
    console.error('Get key reputation error:', error);
    res.status(500).json({
      code: 'SERVER_ERROR',
      message: error.message
    });
  }
};

/**
 * @desc    Report a key
 * @route   POST /api/directory/keys/:keyId/report
 * @access  Private (General API Key)
 */
exports.reportKey = async (req, res) => {
  try {
    const { reason, details, evidence } = req.body;
    
    // Find key
    const key = await Key.findById(req.params.keyId);
    
    if (!key) {
      return res.status(404).json({
        code: 'NOT_FOUND',
        message: 'Key not found'
      });
    }
    
    // Increment reports count
    key.reports += 1;
    
    // Adjust trust score based on reports
    // This is a simple implementation - in a real system, you would have a more sophisticated algorithm
    key.trustScore = Math.max(0, key.trustScore - 0.05);
    
    await key.save();
    
    // In a real implementation, you would store the report details in a separate collection
    
    res.status(201).json({
      reportId: Date.now().toString(), // Placeholder for a real report ID
      status: 'PENDING'
    });
  } catch (error) {
    console.error('Report key error:', error);
    res.status(400).json({
      code: 'BAD_REQUEST',
      message: error.message
    });
  }
};

/**
 * @desc    Search signed content
 * @route   GET /api/directory/content
 * @access  Public
 */
exports.searchSignedContent = async (req, res) => {
  try {
    const { contentHash, authorId, domain, claim, page = 1, limit = 20 } = req.query;
    
    // Build query
    const query = {};
    if (contentHash) query.contentHash = contentHash;
    if (authorId) query.authorId = authorId;
    if (domain) query.domain = domain;
    if (claim) {
      const [claimName, claimValue] = claim.split(':');
      query[`claims.${claimName}`] = claimValue;
    }
    
    // Pagination
    const skip = (parseInt(page) - 1) * parseInt(limit);
    
    // Execute query with aggregation to join with Author model
    const signatures = await ContentSignature.aggregate([
      {
        $match: query
      },
      {
        $lookup: {
          from: 'authors',
          localField: 'authorId',
          foreignField: '_id',
          as: 'author'
        }
      },
      {
        $unwind: '$author'
      },
      {
        $skip: skip
      },
      {
        $limit: parseInt(limit)
      },
      {
        $project: {
          _id: 1,
          contentHash: 1,
          domain: 1,
          authorId: 1,
          signature: 1,
          claims: 1,
          createdAt: 1,
          occurrences: 1,
          author: 1
        }
      }
    ]);
    
    // Get total count
    const total = await ContentSignature.countDocuments(query);
    
    res.status(200).json({
      signatures,
      pagination: {
        total,
        pages: Math.ceil(total / parseInt(limit)),
        page: parseInt(page),
        limit: parseInt(limit)
      }
    });
  } catch (error) {
    console.error('Search signed content error:', error);
    res.status(500).json({
      code: 'SERVER_ERROR',
      message: error.message
    });
  }
};

/**
 * @desc    Find content occurrences
 * @route   GET /api/directory/content/:contentHash/occurrences
 * @access  Public
 */
exports.findContentOccurrences = async (req, res) => {
  try {
    const { page = 1, limit = 20 } = req.query;
    
    // Find signatures with this content hash
    const signatures = await ContentSignature.find({
      contentHash: req.params.contentHash
    });
    
    if (signatures.length === 0) {
      return res.status(404).json({
        code: 'NOT_FOUND',
        message: 'Content hash not found'
      });
    }
    
    // Get signature IDs
    const signatureIds = signatures.map(sig => sig._id);
    
    // Pagination
    const skip = (parseInt(page) - 1) * parseInt(limit);
    
    // Find occurrences
    const occurrences = await ContentOccurrence.find({
      signatureId: { $in: signatureIds }
    })
      .skip(skip)
      .limit(parseInt(limit))
      .sort({ firstSeen: -1 });
    
    // Get total count
    const total = await ContentOccurrence.countDocuments({
      signatureId: { $in: signatureIds }
    });
    
    res.status(200).json({
      occurrences,
      pagination: {
        total,
        pages: Math.ceil(total / parseInt(limit)),
        page: parseInt(page),
        limit: parseInt(limit)
      }
    });
  } catch (error) {
    console.error('Find content occurrences error:', error);
    res.status(500).json({
      code: 'SERVER_ERROR',
      message: error.message
    });
  }
};

/**
 * @desc    Report content misuse
 * @route   POST /api/directory/content/report
 * @access  Private (General API Key)
 */
exports.reportContentMisuse = async (req, res) => {
  try {
    const { contentHash, sourceUrl, targetUrl, reason, details } = req.body;
    
    // Find signatures with this content hash
    const signatures = await ContentSignature.find({
      contentHash
    });
    
    if (signatures.length === 0) {
      return res.status(404).json({
        code: 'NOT_FOUND',
        message: 'Content hash not found'
      });
    }
    
    // In a real implementation, you would store the report details in a separate collection
    
    res.status(201).json({
      reportId: Date.now().toString(), // Placeholder for a real report ID
      status: 'PENDING'
    });
  } catch (error) {
    console.error('Report content misuse error:', error);
    res.status(400).json({
      code: 'BAD_REQUEST',
      message: error.message
    });
  }
};