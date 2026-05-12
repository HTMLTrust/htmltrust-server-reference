const Author = require('../models/Author');
const Key = require('../models/Key');
const ContentSignature = require('../models/ContentSignature');
const ContentOccurrence = require('../models/ContentOccurrence');
const { signContent, verifySignature } = require('../utils/crypto');

/**
 * Build the canonical binding string that is actually signed.
 *
 * Per HTMLTrust spec §2.1, the signature binds four values with colon
 * separators: {content-hash}:{claims-hash}:{domain}:{signed-at}
 *
 * The signer's identity is intentionally NOT included in the binding
 * because it is implicit in keyid resolution: any attempt to claim a
 * signature under a different identity would resolve to a different
 * public key and fail verification.
 */
const buildBinding = ({ contentHash, claimsHash, domain, signedAt }) => {
  if (!contentHash || !claimsHash || !domain || !signedAt) {
    throw new Error(
      `Missing required binding field(s): contentHash=${contentHash}, claimsHash=${claimsHash}, domain=${domain}, signedAt=${signedAt}`
    );
  }
  return `${contentHash}:${claimsHash}:${domain}:${signedAt}`;
};

/**
 * @desc    Sign content
 * @route   POST /api/content/sign
 * @access  Private (Author API Key)
 *
 * Request body:
 *   - contentHash: string, already-hashed canonical content (e.g. "sha256:...")
 *   - claimsHash:  string, already-hashed canonical claims serialization
 *   - domain:      string, publication origin
 *   - signedAt:    string, ISO-8601 timestamp
 *   - claims:      object, full claims map (stored for serving back to verifiers)
 */
exports.signContent = async (req, res) => {
  try {
    const { contentHash, claimsHash, domain, signedAt, claims } = req.body;
    const author = req.author;

    // Get author's private key
    const key = await Key.findOne({ authorId: author._id }).select('+privateKey');

    if (!key) {
      return res.status(404).json({
        code: 'NOT_FOUND',
        message: 'Key not found for this author'
      });
    }

    // Build canonical binding per spec §2.1
    const dataToSign = buildBinding({ contentHash, claimsHash, domain, signedAt });

    // Sign the binding string
    const signature = signContent(dataToSign, key.privateKey, key.algorithm);

    // Check if a signature already exists for this content, domain, and author
    let contentSignature = await ContentSignature.findOne({
      contentHash,
      domain,
      authorId: author._id
    });

    if (contentSignature) {
      // Update existing signature
      contentSignature.signature = signature;
      contentSignature.claims = claims;
      contentSignature.claimsHash = claimsHash;
      contentSignature.signedAt = signedAt;
      contentSignature.occurrences += 1;
      await contentSignature.save();
    } else {
      // Create new signature
      contentSignature = await ContentSignature.create({
        contentHash,
        claimsHash,
        signedAt,
        domain,
        authorId: author._id,
        keyId: key._id,
        signature,
        claims
      });
    }

    // Return the signature
    res.status(201).json({
      contentHash,
      claimsHash,
      signedAt,
      domain,
      authorId: author._id,
      signature,
      claims,
      createdAt: contentSignature.createdAt
    });
  } catch (error) {
    console.error('Sign content error:', error);
    res.status(400).json({
      code: 'BAD_REQUEST',
      message: error.message
    });
  }
};

/**
 * @desc    Verify content signature
 * @route   POST /api/content/verify
 * @access  Public
 *
 * DEPRECATED: cryptographic verification is a local operation per HTMLTrust
 * spec §3.1; this endpoint is retained as a low-trust convenience and will
 * be removed in a future major version. Clients MUST verify signatures
 * locally (e.g. via SubtleCrypto) — a remote yes/no answer from a directory
 * is by definition not a cryptographic guarantee, since the directory is
 * not part of the trust root. The directory's role is to serve public keys,
 * endorsements, and reputation data; it is not an oracle for signature
 * validity.
 *
 * Responses include the HTTP `Deprecation: true` header (RFC 9745) and a
 * `Link` header pointing at the relevant spec section to advertise the
 * deprecation to clients.
 *
 * Request body:
 *   - contentHash: string
 *   - claimsHash:  string
 *   - domain:      string
 *   - signedAt:    string (ISO-8601)
 *   - authorId:    string
 *   - signature:   string (base64)
 */
exports.verifyContent = async (req, res) => {
  // Advertise deprecation per RFC 9745.
  res.set('Deprecation', 'true');
  res.set('Link', '<https://htmltrust.dev/spec#section-3-1>; rel="deprecation"');
  try {
    const { contentHash, claimsHash, domain, signedAt, authorId, signature } = req.body;

    // Get author
    const author = await Author.findById(authorId);

    if (!author) {
      return res.status(404).json({
        code: 'NOT_FOUND',
        message: 'Author not found'
      });
    }

    // Get author's public key
    const key = await Key.findOne({ authorId });

    if (!key) {
      return res.status(404).json({
        code: 'NOT_FOUND',
        message: 'Public key not found'
      });
    }

    // Build canonical binding per spec §2.1
    let valid = false;
    try {
      const dataToVerify = buildBinding({ contentHash, claimsHash, domain, signedAt });
      valid = verifySignature(dataToVerify, signature, key.publicKey, key.algorithm);
    } catch (err) {
      // Missing binding fields -> invalid signature
      valid = false;
    }

    // Get claims if signature is valid
    let claims = {};
    if (valid) {
      // Find the content signature
      const contentSignature = await ContentSignature.findOne({
        contentHash,
        domain,
        authorId
      });

      if (contentSignature) {
        claims = contentSignature.claims;

        // Increment verified signatures count
        key.verifiedSignatures += 1;
        await key.save();
      }
    }

    // Return verification result
    res.status(200).json({
      valid,
      author,
      claims
    });
  } catch (error) {
    console.error('Verify content error:', error);
    res.status(400).json({
      code: 'BAD_REQUEST',
      message: error.message
    });
  }
};

/**
 * @desc    Register content occurrence
 * @route   POST /api/content/occurrences
 * @access  Private (General API Key)
 */
exports.registerOccurrence = async (req, res) => {
  try {
    const { contentHash, claimsHash, signedAt, url, domain, authorId, signature } = req.body;

    // Verify the signature if provided
    let signatureValid = false;
    let signatureId = null;

    if (signature && authorId && claimsHash && signedAt) {
      // Get author's public key
      const key = await Key.findOne({ authorId });

      if (key) {
        // Build canonical binding per spec §2.1
        try {
          const dataToVerify = buildBinding({ contentHash, claimsHash, domain, signedAt });
          signatureValid = verifySignature(dataToVerify, signature, key.publicKey, key.algorithm);
        } catch (err) {
          signatureValid = false;
        }

        if (signatureValid) {
          // Find or create the content signature
          let contentSignature = await ContentSignature.findOne({
            contentHash,
            domain,
            authorId
          });

          if (!contentSignature) {
            contentSignature = await ContentSignature.create({
              contentHash,
              claimsHash,
              signedAt,
              domain,
              authorId,
              keyId: key._id,
              signature
            });
          }

          signatureId = contentSignature._id;
        }
      }
    }

    // Check if occurrence already exists
    let occurrence = await ContentOccurrence.findOne({
      signatureId,
      url
    });

    if (occurrence) {
      // Update last seen timestamp
      occurrence.lastSeen = Date.now();
      occurrence.signatureValid = signatureValid;
      await occurrence.save();
    } else {
      // Create new occurrence
      occurrence = await ContentOccurrence.create({
        signatureId,
        url,
        domain,
        signatureValid
      });
    }

    res.status(201).json(occurrence);
  } catch (error) {
    console.error('Register occurrence error:', error);
    res.status(400).json({
      code: 'BAD_REQUEST',
      message: error.message
    });
  }
};