const Key = require('../models/Key');
const Author = require('../models/Author');
const ContentSignature = require('../models/ContentSignature');
const ContentOccurrence = require('../models/ContentOccurrence');
const {
  detailFor,
  keyDocumentFor,
  normalizeSerializedOrigin,
  problem,
  safeSearchRegex,
} = require('../utils/htmltrustProtocol');
const { directoryBaseUrl, directoryKeyUrl, publicKeyId } = require('../utils/directoryUrl');
const { negotiatedType } = require('../middleware/contentNegotiation');

/**
 * Clamp caller-supplied pagination. An unbounded `limit` turns a public read
 * endpoint into a bulk-export and a memory-pressure lever.
 */
const MAX_PAGE_SIZE = 100;
const boundedLimit = (value, fallback = 20) => {
  const parsed = parseInt(value, 10);
  if (!Number.isFinite(parsed) || parsed < 1) return fallback;
  return Math.min(parsed, MAX_PAGE_SIZE);
};
const boundedPage = (value) => {
  const parsed = parseInt(value, 10);
  if (!Number.isFinite(parsed) || parsed < 1) return 1;
  return parsed;
};

const baseDirectoryUrl = (req) => `${directoryBaseUrl(req)}/`;

const keyIdFromSignerId = (id) => {
  if (!id || typeof id !== 'string') return null;
  if (/^[0-9a-fA-F]{24}$/.test(id)) return id;
  try {
    const url = new URL(id);
    const segments = url.pathname.split('/').filter(Boolean);
    const keyIndex = segments.lastIndexOf('keys');
    if (keyIndex !== -1 && segments[keyIndex + 1]) {
      return decodeURIComponent(segments[keyIndex + 1]);
    }
  } catch {}
  return null;
};

const OPAQUE_KEY_ID = /^k_[A-Za-z0-9_-]{20,64}$/;
const MONGO_KEY_ID = /^[0-9a-fA-F]{24}$/;

const decodedKeyId = (value) => {
  if (typeof value !== 'string') return null;
  let decoded;
  try {
    decoded = decodeURIComponent(value);
  } catch {
    return null;
  }
  return MONGO_KEY_ID.test(decoded) || OPAQUE_KEY_ID.test(decoded) ? decoded : null;
};

// New keys are addressed by their opaque publicId. Existing rows remain
// readable through their historical Mongo ObjectId until they are migrated.
const findDirectoryKey = async (value) => {
  const id = decodedKeyId(value);
  if (!id) return null;
  if (MONGO_KEY_ID.test(id)) {
    const legacy = await Key.findById(id);
    if (legacy) return legacy;
  }
  return Key.findOne({ publicId: id });
};

exports.discovery = async (req, res) => {
  res
    .type(negotiatedType(req, 'application/htmltrust-directory+json'))
    .status(200)
    .json({
      directory: baseDirectoryUrl(req),
      version: '1',
      capabilities: {
        content: true,
        endorsements: true,
        keys: true,
        reputation: true
      },
      supportedAlgorithms: {
        signature: [
          'ed25519',
          'ecdsa-p256',
          'ecdsa-p384',
          'rsa-pss-sha256',
          'rsa-pkcs1-sha256'
        ],
        hash: ['sha256', 'sha384', 'sha512']
      },
      supportedProfiles: ['htmltrust-signature-v1']
    });
};

exports.getKeyDocument = async (req, res) => {
  const id = decodedKeyId(req.params.id);
  if (!id) {
    return problem(res, 400, 'Invalid key id', 'The key id must be a valid opaque path identifier');
  }

  try {
    const key = await findDirectoryKey(id);
    if (!key) {
      return problem(res, 404, 'Key not found', 'No key document exists for the requested id');
    }
    res
      .type(negotiatedType(req, 'application/htmltrust-key+json'))
      .status(200)
      .json(keyDocumentFor(key, directoryKeyUrl(req, publicKeyId(key))));
  } catch (error) {
    console.error('Get key document error:', error);
    return problem(res, 500, 'Directory read failure', 'The directory could not read the key document', {
      type: 'https://htmltrust.org/errors/storage-failure',
    });
  }
};

exports.getSignerReputation = async (req, res) => {
  let signerId;
  try {
    signerId = decodeURIComponent(req.params.id);
  } catch (error) {
    return problem(res, 400, 'Invalid signer id', 'The signer id is not valid percent-encoding');
  }

  try {
    const keyId = keyIdFromSignerId(signerId);
    let key = null;
    if (keyId) {
      key = await findDirectoryKey(keyId);
    }
    if (!key && OPAQUE_KEY_ID.test(signerId)) {
      key = await findDirectoryKey(signerId);
    }
    if (!key && /^[0-9a-fA-F]{24}$/.test(signerId)) {
      key = await Key.findOne({ authorId: signerId });
    }
    if (!key) {
      return problem(res, 404, 'Signer not found', 'No local signer reputation exists for the requested id', {
        keyid: signerId,
      });
    }

    res.status(200).json({
      keyid: signerId,
      score: key.trustScore,
      asOf: (key.updatedAt || key.createdAt || new Date()).toISOString(),
      components: ['verified-signatures', 'reports'],
      methodology: `${baseDirectoryUrl(req)}methodology/reputation-v1`
    });
  } catch (error) {
    console.error('Get signer reputation error:', error);
    return problem(res, 500, 'Directory read failure', 'The directory could not read signer reputation', {
      type: 'https://htmltrust.org/errors/storage-failure',
    });
  }
};

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
    
    // Join with Author model to filter by author name and key type.
    //
    // `authorName` is unauthenticated caller input on a public route. Passing
    // it straight into $regex let the caller supply pattern syntax — both a
    // NoSQL injection (the filter no longer means what the code says) and a
    // denial of service (a catastrophically backtracking pattern is evaluated
    // per document inside the database). safeSearchRegex escapes, caps, and
    // anchors it into a literal prefix match.
    const authorQuery = {};
    if (authorName) authorQuery['author.name'] = safeSearchRegex(authorName, 'authorName');
    if (keyType) authorQuery['author.keyType'] = String(keyType);
    
    // Filter by trust score
    if (minTrustScore) query.trustScore = { $gte: parseFloat(minTrustScore) };
    const normalizedDomain = domain ? normalizeSerializedOrigin(domain) : null;

    // Pagination. `limit` is caller-controlled, so it is clamped: an
    // unbounded page size lets one request pull the whole collection.
    const pageNumber = boundedPage(page);
    const pageSize = boundedLimit(limit);
    const skip = (pageNumber - 1) * pageSize;

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
          ...authorQuery
        }
      },
      {
        $skip: skip
      },
      {
        $limit: pageSize
      },
      {
        $project: {
          _id: 1,
          publicId: 1,
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
    const publicKeys = keys.map((key) => ({
      ...key,
      id: key.publicId || String(key._id),
    }));
    
    res.status(200).json({
      keys: normalizedDomain
        ? publicKeys.filter((key) => key.author && key.author.url && key.author.url.startsWith(normalizedDomain))
        : publicKeys,
      pagination: {
        total,
        pages: Math.ceil(total / pageSize),
        page: pageNumber,
        limit: pageSize
      }
    });
  } catch (error) {
    if (error.expose) {
      return problem(res, 400, 'Invalid query', error.message);
    }
    console.error('Search public keys error:', error);
    res.status(500).json({
      code: 'SERVER_ERROR',
      message: detailFor(error)
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
    const key = await findDirectoryKey(req.params.keyId);
    
    if (!key) {
      return res.status(404).json({
        code: 'NOT_FOUND',
        message: 'Key not found'
      });
    }
    
    res.status(200).json({
      keyId: publicKeyId(key),
      trustScore: key.trustScore,
      verifiedSignatures: key.verifiedSignatures,
      reports: key.reports,
      lastUpdated: key.updatedAt || key.createdAt
    });
  } catch (error) {
    console.error('Get key reputation error:', error);
    res.status(500).json({
      code: 'SERVER_ERROR',
      message: detailFor(error)
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
    const key = await findDirectoryKey(req.params.keyId);
    
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
      message: detailFor(error)
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
    if (domain) query.domain = normalizeSerializedOrigin(domain);
    if (claim) {
      const [claimName, claimValue] = claim.split(':');
      query[`claims.${claimName}`] = claimValue;
    }
    
    // Pagination (clamped; see boundedLimit)
    const pageNumber = boundedPage(page);
    const pageSize = boundedLimit(limit);
    const skip = (pageNumber - 1) * pageSize;
    
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
        $limit: pageSize
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
        pages: Math.ceil(total / pageSize),
        page: pageNumber,
        limit: pageSize
      }
    });
  } catch (error) {
    console.error('Search signed content error:', error);
    res.status(500).json({
      code: 'SERVER_ERROR',
      message: detailFor(error)
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
    
    // Pagination (clamped; see boundedLimit)
    const pageNumber = boundedPage(page);
    const pageSize = boundedLimit(limit);
    const skip = (pageNumber - 1) * pageSize;
    
    // Find occurrences
    const occurrences = await ContentOccurrence.find({
      signatureId: { $in: signatureIds }
    })
      .skip(skip)
      .limit(pageSize)
      .sort({ firstSeen: -1 });
    
    // Get total count
    const total = await ContentOccurrence.countDocuments({
      signatureId: { $in: signatureIds }
    });
    
    res.status(200).json({
      occurrences,
      pagination: {
        total,
        pages: Math.ceil(total / pageSize),
        page: pageNumber,
        limit: pageSize
      }
    });
  } catch (error) {
    console.error('Find content occurrences error:', error);
    res.status(500).json({
      code: 'SERVER_ERROR',
      message: detailFor(error)
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
      message: detailFor(error)
    });
  }
};
