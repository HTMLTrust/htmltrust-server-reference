const Author = require('../models/Author');
const Key = require('../models/Key');
const ContentSignature = require('../models/ContentSignature');
const { resolveUsableKey } = require('../utils/keyResolution');
const ContentOccurrence = require('../models/ContentOccurrence');
const Endorsement = require('../models/Endorsement');
const { hashCanonical, signContent, verifySignature } = require('../utils/crypto');
const {
  assertContentHash,
  assertRfc3339Utc,
  decodeCanonicalBase64,
  detailFor,
  invalid,
  normalizeClaims,
  normalizeAlgorithm,
  normalizeSerializedOrigin,
  problem,
  signedAtFromClaims,
} = require('../utils/htmltrustProtocol');
const { canonicalizeClaims } = require('../utils/claims');
const { directoryKeyUrl } = require('../utils/directoryUrl');

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
    throw invalid(
      `Missing required binding field(s): contentHash=${contentHash}, claimsHash=${claimsHash}, domain=${domain}, signedAt=${signedAt}`
    );
  }
  return `${contentHash}:${claimsHash}:${domain}:${signedAt}`;
};

const claimsObject = (claims) => Object.fromEntries(
  normalizeClaims(claims).map((claim) => [claim.name, claim.content])
);

/**
 * Hash of the canonical claims serialization, draft §4.6.
 *
 * The canonicalization itself lives in src/utils/claims.js on top of the
 * shared @htmltrust/canonicalization text normalizer, so this server produces
 * the same bytes as the signers do. The previous implementation here sorted
 * whole `name:content` lines with JavaScript's default UTF-16 comparison, did
 * not normalize the claim text at all, and invented a `signed-at` claim when
 * one was absent — each of which yields a different claims hash than a
 * conforming signer computes, so a correctly signed submission failed to
 * verify (and an incorrectly signed one could pass).
 */
const canonicalClaimsHash = async (claims, hashAlgorithm) => {
  if (hashAlgorithm !== 'sha256') {
    throw invalid('This reference server currently computes claimsHash values with sha256 only');
  }
  return hashCanonical(await canonicalizeClaims(normalizeClaims(claims)));
};

const validateSignatureInputs = ({ contentHash, claimsHash, domain, signedAt, signature }) => {
  const normalizedContentHash = assertContentHash(contentHash, 'contentHash');
  const normalizedClaimsHash = assertContentHash(claimsHash, 'claimsHash');
  const contentAlgorithm = normalizedContentHash.split(':')[0];
  const claimsAlgorithm = normalizedClaimsHash.split(':')[0];
  if (contentAlgorithm !== claimsAlgorithm) {
    throw invalid('contentHash and claimsHash must use the same hash algorithm');
  }
  const normalizedDomain = normalizeSerializedOrigin(domain);
  assertRfc3339Utc(signedAt, 'signedAt');
  if (signature) {
    decodeCanonicalBase64(signature, 'signature');
  }
  return {
    contentHash: normalizedContentHash,
    claimsHash: normalizedClaimsHash,
    domain: normalizedDomain,
    signedAt,
  };
};

const keyidFor = (req, key) => directoryKeyUrl(req, key._id);

/**
 * Resolve a submitted keyid to a usable key, honouring revocation and expiry
 * (draft §8). Falls back to the legacy "keyid is an author id" form that
 * earlier clients used.
 */
const resolveSubmissionKey = async (req, keyid) => {
  const resolution = await resolveUsableKey(keyid, { req });
  if (resolution.ok) return resolution;

  if (/^[0-9a-fA-F]{24}$/.test(keyid || '')) {
    const key = await Key.findOne({ authorId: keyid });
    if (key && !key.revoked) {
      return {
        ok: true,
        resolved: {
          keyid,
          publicKeyPem: key.publicKey,
          algorithm: key.algorithm,
          key,
        },
      };
    }
  }

  return resolution;
};

const contentRecord = async (req, contentHash) => {
  const signatures = await ContentSignature.find({ contentHash }).sort({ createdAt: 1 });
  if (signatures.length === 0) return null;

  const signers = await Promise.all(signatures.map(async (signature) => {
    const key = await Key.findById(signature.keyId);
    return {
      keyid: key ? keyidFor(req, key) : String(signature.keyId),
      signedAt: signature.signedAt,
      domain: signature.domain,
      signature: signature.signature,
    };
  }));

  const endorsementCount = await Endorsement.countDocuments({
    $or: [{ endorsement: contentHash }, { contentHash }],
  });

  return {
    contentHash,
    firstSeen: signatures[0].createdAt.toISOString(),
    signers,
    endorsementCount,
  };
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
    const { claims } = req.body;
    const {
      contentHash,
      claimsHash,
      domain,
      signedAt,
    } = validateSignatureInputs(req.body);
    const author = req.author;
    const claimSignedAt = signedAtFromClaims(claims);
    if (claimSignedAt && claimSignedAt !== signedAt) {
      throw invalid('signedAt must match the direct child signed-at claim');
    }

    // Recompute the claims hash from the claims map rather than signing the
    // caller's value. The binding (§5) is what the signature attests to; if
    // the directory signs a claimsHash it never derived, the caller chooses
    // what the key attests to and the stored claims are free to say something
    // else entirely.
    const recomputedClaimsHash = await canonicalClaimsHash(claims, contentHash.split(':')[0]);
    if (recomputedClaimsHash !== claimsHash) {
      throw invalid(
        `claimsHash does not match the canonical claims serialization (computed ${recomputedClaimsHash})`
      );
    }

    // Get author's private key
    const key = await Key.findOne({ authorId: author._id }).select('+privateKey');

    if (!key) {
      return res.status(404).json({
        code: 'NOT_FOUND',
        message: 'Key not found for this author'
      });
    }

    if (!key.privateKey) {
      // The author registered their own public key, so the directory has no
      // private half to sign with and must not pretend otherwise.
      return problem(
        res,
        400,
        'No directory-held signing key',
        'This author registered its own public key; content must be signed by the author and submitted to POST /content'
      );
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
      contentSignature.claims = claimsObject(claims);
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
        claims: claimsObject(claims)
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
      keyid: keyidFor(req, key),
      algorithm: normalizeAlgorithm(key.algorithm),
      claims: claimsObject(claims),
      createdAt: contentSignature.createdAt
    });
  } catch (error) {
    console.error('Sign content error:', error);
    res.status(400).json({
      code: 'BAD_REQUEST',
      message: detailFor(error)
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
    const { authorId, signature } = req.body;
    const {
      contentHash,
      claimsHash,
      domain,
      signedAt,
    } = validateSignatureInputs(req.body);

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
      message: detailFor(error)
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
    const { url, authorId, signature } = req.body;
    const domain = normalizeSerializedOrigin(req.body.domain);
    const contentHash = assertContentHash(req.body.contentHash, 'contentHash');
    let claimsHash = req.body.claimsHash;
    let signedAt = req.body.signedAt;
    if (signature) {
      ({ claimsHash, signedAt } = validateSignatureInputs(req.body));
    }

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
      message: detailFor(error)
    });
  }
};

/**
 * @desc    Retrieve a draft-shaped content record
 * @route   GET /api/content/:contentHash
 * @access  Public
 */
exports.getContentRecord = async (req, res) => {
  try {
    const contentHash = assertContentHash(req.params.contentHash, 'contentHash');
    const record = await contentRecord(req, contentHash);
    if (!record) {
      return problem(res, 404, 'Content not found', 'No content record exists for the requested hash', {
        contentHash,
      });
    }
    res.type('application/htmltrust-content+json').status(200).json(record);
  } catch (error) {
    return problem(res, 400, 'Invalid content hash', detailFor(error));
  }
};

/**
 * @desc    Submit a draft-shaped signed content occurrence
 * @route   POST /api/content
 * @access  Private (General API Key)
 */
exports.submitContent = async (req, res) => {
  try {
    const { keyid, sourceURL, signature, claims = [] } = req.body;
    if (!keyid || !signature || !sourceURL) {
      return problem(res, 400, 'Invalid content submission', 'keyid, signature, and sourceURL are required');
    }

    const contentHash = assertContentHash(req.body.contentHash, 'contentHash');
    const signedAt = assertRfc3339Utc(req.body.signedAt, 'signedAt');
    const domain = normalizeSerializedOrigin(req.body.domain);
    const hashAlgorithm = contentHash.split(':')[0];
    const claimsHash = req.body.claimsHash
      ? assertContentHash(req.body.claimsHash, 'claimsHash')
      : await canonicalClaimsHash(claims, hashAlgorithm);
    if (claimsHash.split(':')[0] !== hashAlgorithm) {
      throw invalid('contentHash and claimsHash must use the same hash algorithm');
    }

    const resolution = await resolveSubmissionKey(req, keyid);
    if (!resolution.ok) {
      return problem(res, 400, 'Key resolution failed', `The submitted keyid could not be resolved (${resolution.reason})`, {
        type: `https://htmltrust.org/errors/${resolution.reason}`,
        keyid,
      });
    }
    const key = resolution.resolved.key;
    if (!key) {
      // Remote keys resolve to key material but not to a local author record,
      // and every stored ContentSignature is keyed by author. Indexing
      // externally-held keys needs a local registration first.
      return problem(res, 400, 'Key resolution failed', 'The submitted keyid is not registered with this directory', {
        type: 'https://htmltrust.org/errors/key-resolution-failed',
        keyid,
      });
    }

    const binding = buildBinding({ contentHash, claimsHash, domain, signedAt });
    if (!verifySignature(binding, signature, resolution.resolved.publicKeyPem, resolution.resolved.algorithm)) {
      return problem(res, 400, 'Signature verification failed', 'The submitted signature did not verify against the canonical signing payload.', {
        type: 'https://htmltrust.org/errors/signature-invalid',
        contentHash,
      });
    }

    let contentSignature = await ContentSignature.findOne({
      contentHash,
      domain,
      authorId: key.authorId,
    });
    if (contentSignature) {
      contentSignature.signature = signature;
      contentSignature.claimsHash = claimsHash;
      contentSignature.signedAt = signedAt;
      contentSignature.claims = claimsObject(claims);
      contentSignature.occurrences += 1;
      await contentSignature.save();
    } else {
      contentSignature = await ContentSignature.create({
        contentHash,
        claimsHash,
        signedAt,
        domain,
        authorId: key.authorId,
        keyId: key._id,
        signature,
        claims: claimsObject(claims),
      });
    }

    await ContentOccurrence.findOneAndUpdate(
      { signatureId: contentSignature._id, url: sourceURL },
      {
        signatureId: contentSignature._id,
        url: sourceURL,
        domain,
        signatureValid: true,
        lastSeen: Date.now(),
      },
      { upsert: true, setDefaultsOnInsert: true }
    );

    const record = await contentRecord(req, contentHash);
    res
      .status(201)
      .location(`/api/content/${encodeURIComponent(contentHash)}`)
      .type('application/htmltrust-content+json')
      .json(record);
  } catch (error) {
    return problem(res, 400, 'Invalid content submission', detailFor(error));
  }
};

exports.listContentEndorsements = async (req, res) => {
  try {
    const contentHash = assertContentHash(req.params.contentHash, 'contentHash');
    const endorsements = await Endorsement.find({
      $or: [{ endorsement: contentHash }, { contentHash }],
    }).sort({ createdAt: -1 });
    const { toEndorsementDocument } = require('./endorsementController');
    res
      .type('application/htmltrust-endorsement+json')
      .status(200)
      .json(endorsements.map(toEndorsementDocument));
  } catch (error) {
    return problem(res, 400, 'Invalid content hash', detailFor(error));
  }
};
