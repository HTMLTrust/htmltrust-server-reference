const Endorsement = require('../models/Endorsement');
const Author = require('../models/Author');
const Key = require('../models/Key');
const { verifySignature } = require('../utils/crypto');

/**
 * Build the canonical rawBlob for an endorsement when the client did not
 * supply one. The wire format follows the example in spec §2.5:
 *
 *   {
 *     "endorser": "did:web:publisher.org",
 *     "endorsement": "sha256-XYZ",
 *     "signature": "BASE64_SIG",
 *     "timestamp": "2025-05-01T00:00Z"
 *   }
 *
 * Keys are emitted in a stable order (endorser, endorsement, signature,
 * timestamp, algorithm) so any verifier that reconstructs the blob from
 * structured fields produces the same bytes. The optional `algorithm` field
 * is omitted when it equals the default 'ed25519' to match the spec example.
 *
 * NOTE: clients SHOULD post their own rawBlob to avoid any ambiguity. This
 * fallback exists for convenience only.
 */
const buildCanonicalBlob = ({ endorser, contentHash, signature, timestamp, algorithm }) => {
  const obj = {
    endorser,
    endorsement: contentHash,
    signature,
    timestamp
  };
  if (algorithm && algorithm.toLowerCase() !== 'ed25519') {
    obj.algorithm = algorithm;
  }
  return JSON.stringify(obj);
};

/**
 * Best-effort, opportunistic verification of an endorsement's signature.
 *
 * The directory does NOT have authoritative knowledge of every endorser's
 * public key — endorser keyids are opaque strings that clients resolve
 * locally. As a sanity check, we attempt to find a matching Author/Key pair
 * by treating the endorser string as either an Author._id or as a name. If
 * no match is found, we silently store the endorsement as-is; clients verify
 * locally per spec §2.5.
 *
 * Returns true if verification succeeded, false if it failed, or null if no
 * key was available to attempt verification.
 */
const tryVerify = async ({ endorser, contentHash, timestamp, signature, algorithm }) => {
  let key = null;
  try {
    // Look for an Author whose _id or name matches the endorser string.
    let author = null;
    if (/^[0-9a-fA-F]{24}$/.test(endorser)) {
      author = await Author.findById(endorser);
    }
    if (!author) {
      author = await Author.findOne({ name: endorser });
    }
    if (!author) return null;

    key = await Key.findOne({ authorId: author._id });
    if (!key) return null;
  } catch (err) {
    return null;
  }

  try {
    const binding = `${contentHash}:${timestamp}`;
    return verifySignature(binding, signature, key.publicKey, key.algorithm || algorithm);
  } catch (err) {
    return false;
  }
};

/**
 * @desc    Create (or upsert) an endorsement
 * @route   POST /api/endorsements
 * @access  Private (General API Key)
 *
 * Request body fields (all required unless noted):
 *   - endorser:    string (opaque keyid)
 *   - contentHash: string (e.g. "sha256:...")
 *   - signature:   string (base64)
 *   - timestamp:   string (ISO-8601)
 *   - algorithm:   string (optional, default 'ed25519')
 *   - rawBlob:     string (optional; the exact bytes the client signed over.
 *                  If omitted, the server constructs a canonical blob in a
 *                  stable key order. Clients SHOULD post their own rawBlob.)
 */
exports.createEndorsement = async (req, res) => {
  try {
    const { endorser, contentHash, signature, timestamp } = req.body;
    const algorithm = req.body.algorithm || 'ed25519';
    let { rawBlob } = req.body;

    if (!endorser || !contentHash || !signature || !timestamp) {
      return res.status(400).json({
        code: 'BAD_REQUEST',
        message: 'endorser, contentHash, signature, and timestamp are required'
      });
    }

    if (!rawBlob) {
      rawBlob = buildCanonicalBlob({ endorser, contentHash, signature, timestamp, algorithm });
    }

    // Opportunistic sanity check — does NOT block storage. Clients verify
    // locally per spec §2.5.
    const verifyResult = await tryVerify({ endorser, contentHash, timestamp, signature, algorithm });
    if (verifyResult === false) {
      console.warn(
        `Endorsement signature failed opportunistic verification: endorser=${endorser} contentHash=${contentHash}`
      );
    }

    // Upsert: a given endorser may only have one endorsement per content
    // hash. Resubmissions overwrite.
    let endorsement = await Endorsement.findOne({ endorser, contentHash });
    if (endorsement) {
      endorsement.signature = signature;
      endorsement.timestamp = timestamp;
      endorsement.algorithm = algorithm;
      endorsement.rawBlob = rawBlob;
      await endorsement.save();
    } else {
      endorsement = await Endorsement.create({
        endorser,
        contentHash,
        signature,
        timestamp,
        algorithm,
        rawBlob
      });
    }

    res.status(201).json({
      _id: endorsement._id,
      endorser: endorsement.endorser,
      contentHash: endorsement.contentHash,
      signature: endorsement.signature,
      timestamp: endorsement.timestamp,
      algorithm: endorsement.algorithm,
      rawBlob: endorsement.rawBlob,
      createdAt: endorsement.createdAt,
      // Expose the opportunistic verification result for diagnostics. Clients
      // MUST NOT rely on this — they verify locally per spec §2.5.
      opportunisticallyVerified: verifyResult
    });
  } catch (error) {
    console.error('Create endorsement error:', error);
    res.status(400).json({
      code: 'BAD_REQUEST',
      message: error.message
    });
  }
};

/**
 * @desc    List endorsements for a content hash
 * @route   GET /api/endorsements?content-hash=sha256:...
 * @access  Public
 */
exports.listEndorsements = async (req, res) => {
  try {
    // Accept both kebab-case (spec-style) and camelCase query parameters.
    const contentHash = req.query['content-hash'] || req.query.contentHash;

    if (!contentHash) {
      return res.status(400).json({
        code: 'BAD_REQUEST',
        message: 'content-hash query parameter is required'
      });
    }

    const endorsements = await Endorsement.find({ contentHash }).sort({ createdAt: -1 });

    res.status(200).json(
      endorsements.map((e) => ({
        _id: e._id,
        endorser: e.endorser,
        contentHash: e.contentHash,
        signature: e.signature,
        timestamp: e.timestamp,
        algorithm: e.algorithm,
        rawBlob: e.rawBlob,
        createdAt: e.createdAt
      }))
    );
  } catch (error) {
    console.error('List endorsements error:', error);
    res.status(400).json({
      code: 'BAD_REQUEST',
      message: error.message
    });
  }
};

/**
 * @desc    Delete an endorsement
 * @route   DELETE /api/endorsements/:id
 * @access  Private (General API Key)
 *
 * MVP: gated behind the existing API key auth only. A production deployment
 * MUST additionally verify that the caller's authenticated identity matches
 * the endorsement's `endorser` keyid (e.g. by requiring a signed delete
 * request, or by tying the API key to a specific keyid).
 *
 * TODO: enforce caller-keyid match against endorsement.endorser before
 * permitting deletion.
 */
exports.deleteEndorsement = async (req, res) => {
  try {
    const endorsement = await Endorsement.findById(req.params.id);

    if (!endorsement) {
      return res.status(404).json({
        code: 'NOT_FOUND',
        message: 'Endorsement not found'
      });
    }

    await Endorsement.deleteOne({ _id: endorsement._id });

    res.status(204).send();
  } catch (error) {
    console.error('Delete endorsement error:', error);
    res.status(400).json({
      code: 'BAD_REQUEST',
      message: error.message
    });
  }
};
