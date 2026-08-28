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
} = require('../utils/htmltrustProtocol');
const { canonicalizeClaims } = require('../utils/claims');
const { directoryKeyUrl } = require('../utils/directoryUrl');
const {
  buildV1ContentSigningPayload,
  deriveLocation,
  PROFILE,
  validateV1ContentSubmission,
} = require('../utils/signingProfile');
const { negotiatedType } = require('../middleware/contentNegotiation');

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

const contentSignatureConflict = (message) => {
  const error = invalid(message);
  error.statusCode = 409;
  error.problemType = 'https://htmltrust.org/errors/content-signature-conflict';
  return error;
};

const isDuplicateKeyError = (error) => error?.code === 11000 || error?.codeName === 'DuplicateKey';

// A v1 ContentSignature row is an immutable signed artifact. Its identity is
// content + profile + derived location + keyid, while sourceURL is occurrence
// metadata and may differ for an origin-scoped signature.
const matchesV1Artifact = (record, prepared, signature) => (
  record.profile === PROFILE.signature &&
  record.algorithm === prepared.algorithm &&
  record.claimsHash === prepared.claimsHash &&
  record.signedAt === prepared.signedAt &&
  record.scope === prepared.scope &&
  record.signature === signature
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

const contentRecord = async (req, contentHash, { v1Only = false } = {}) => {
  const query = { contentHash };
  if (v1Only) query.profile = 'htmltrust-signature-v1';
  const signatures = await ContentSignature.find(query).sort({ createdAt: 1 });
  if (signatures.length === 0) return null;

  const signers = await Promise.all(signatures.map(async (signature) => {
    const key = await Key.findById(signature.keyId);
    const record = {
      profile: signature.profile || 'legacy-colon-binding',
      keyid: signature.keyid || (key ? keyidFor(req, key) : String(signature.keyId)),
      algorithm: signature.algorithm || (key ? normalizeAlgorithm(key.algorithm) : undefined),
      signedAt: signature.signedAt,
      scope: signature.scope,
      location: signature.location,
      signature: signature.signature,
    };
    if (!signature.profile) record.domain = signature.domain;
    return Object.fromEntries(Object.entries(record).filter(([, value]) => value !== undefined));
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
 * @desc    Sign content with the directory-held v1 convenience key
 * @route   POST /api/content/sign
 * @access  Private (Author API Key)
 *
 * Request body:
 *   - contentHash: string, already-hashed canonical content (e.g. "sha256:...")
 *   - sourceURL:   string, final HTTPS response URL
 *   - scope:       string, either "url" or "origin"
 *   - signedAt:    string, exact v1 UTC timestamp
 *   - claims:      array of {name, content} records, including signed-at
 *
 * The directory derives every other signing field from the authenticated
 * author and the submitted source URL.  This route intentionally has no
 * legacy colon-binding or caller-supplied claims-hash compatibility path.
 */
exports.signContent = async (req, res) => {
  try {
    const author = req.author;
    if (!author || !author._id) {
      return problem(res, 401, 'Unauthorized', 'An authenticated author is required to sign content', {
        type: 'https://htmltrust.org/errors/unauthorized',
      });
    }

    const body = req.body || {};
    // These fields belonged to the removed colon-binding endpoint. Rejecting
    // them catches stale clients instead of silently signing a different
    // interpretation of their request.
    for (const field of ['domain', 'authorId', 'claimsHash']) {
      if (Object.hasOwn(body, field)) {
        throw invalid(`${field} is not accepted by the v1 signing endpoint`);
      }
    }

    // The authenticated author selects the key and all key/profile fields.
    // A client may echo them for diagnostics, but cannot choose a different
    // key or algorithm for the directory-held private key.
    const keyQuery = Key.findOne({
      authorId: author._id,
      revoked: { $ne: true },
      $or: [
        { expiresAt: { $exists: false } },
        { expiresAt: null },
        { expiresAt: { $gt: new Date() } },
      ],
    });
    // Rotation creates a new key while the old key remains resolvable for
    // historical signatures. The newest usable key is the current convenience
    // signing key under the existing Key schema, with _id as a stable tie
    // breaker for equal timestamps.
    const key = await keyQuery.sort({ createdAt: -1, _id: -1 }).select('+privateKey');

    if (!key) {
      return problem(res, 404, 'Signing key not found', 'No active directory-held signing key exists for this author', {
        type: 'https://htmltrust.org/errors/signing-key-not-found',
        authorId: String(author._id),
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

    const keyid = keyidFor(req, key);
    const algorithm = normalizeAlgorithm(key.algorithm);
    const location = deriveLocation(body.sourceURL, body.scope);
    const expectedFields = {
      profile: PROFILE.signature,
      context: PROFILE.context,
      canonicalizationProfile: PROFILE.canonicalization,
      attributeProfile: PROFILE.attributes,
      urlProfile: PROFILE.url,
      keyid,
      algorithm,
      location,
    };
    for (const [field, expected] of Object.entries(expectedFields)) {
      if (Object.hasOwn(body, field) && body[field] !== expected) {
        throw invalid(`${field} must equal the directory-selected v1 value`);
      }
    }

    const prepared = await buildV1ContentSigningPayload({
      ...body,
      profile: PROFILE.signature,
      keyid,
      algorithm,
      location,
    });
    const signature = signContent(prepared.payload, key.privateKey, algorithm);
    const sourceOrigin = new URL(prepared.sourceURL).origin;

    // v1 identity is content + derived location + exact key identifier. A
    // signature can occur at more than one URL when its scope is origin.
    const identity = {
      contentHash: prepared.contentHash,
      profile: PROFILE.signature,
      location: prepared.location,
      keyid,
    };
    let contentSignature = await ContentSignature.findOne(identity);

    if (contentSignature && !matchesV1Artifact(contentSignature, prepared, signature)) {
      throw contentSignatureConflict(
        'A different signed payload already exists for this content, location, and key',
      );
    }

    if (!contentSignature) {
      try {
        contentSignature = await ContentSignature.create({
          ...identity,
          claimsHash: prepared.claimsHash,
          signedAt: prepared.signedAt,
          domain: sourceOrigin,
          algorithm,
          scope: prepared.scope,
          sourceURL: prepared.sourceURL,
          authorId: author._id,
          keyId: key._id,
          signature,
          claims: claimsObject(prepared.claims),
        });
      } catch (error) {
        // Two identical first submissions can race the unique v1 identity
        // index. Re-read the winner and treat it as an idempotent retry. A
        // different payload still receives the explicit conflict response.
        if (!isDuplicateKeyError(error)) throw error;
        contentSignature = await ContentSignature.findOne(identity);
        if (!contentSignature) throw error;
        if (!matchesV1Artifact(contentSignature, prepared, signature)) {
          throw contentSignatureConflict(
            'A different signed payload already exists for this content, location, and key',
          );
        }
      }
    }

    await ContentOccurrence.findOneAndUpdate(
      { signatureId: contentSignature._id, url: prepared.sourceURL },
      {
        signatureId: contentSignature._id,
        url: prepared.sourceURL,
        domain: sourceOrigin,
        signatureValid: true,
        lastSeen: Date.now(),
      },
      { upsert: true, setDefaultsOnInsert: true },
    );

    // Return the complete v1 attribute set, so the caller can publish a
    // signed-section without reconstructing any cryptographic field.
    res.status(201).json({
      profile: PROFILE.signature,
      context: PROFILE.context,
      canonicalizationProfile: PROFILE.canonicalization,
      attributeProfile: PROFILE.attributes,
      urlProfile: PROFILE.url,
      contentHash: prepared.contentHash,
      claimsHash: prepared.claimsHash,
      signedAt: prepared.signedAt,
      scope: prepared.scope,
      location: prepared.location,
      sourceURL: prepared.sourceURL,
      domain: sourceOrigin,
      authorId: author._id,
      signature,
      keyid,
      algorithm,
      claims: prepared.claims,
      createdAt: contentSignature.createdAt
    });
  } catch (error) {
    console.error('Sign content error:', error);
    const status = error.statusCode || 400;
    return problem(res, status, status === 409 ? 'Content signature conflict' : 'Invalid v1 signing request', detailFor(error), {
      type: error.problemType || 'https://htmltrust.org/errors/content-signing-invalid',
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
  let contentHash;
  try {
    contentHash = assertContentHash(req.params.contentHash, 'contentHash');
  } catch (error) {
    return problem(res, 400, 'Invalid content hash', detailFor(error));
  }

  try {
    const record = await contentRecord(req, contentHash);
    if (!record) {
      return problem(res, 404, 'Content not found', 'No content record exists for the requested hash', {
        contentHash,
      });
    }
    res.type(negotiatedType(req, 'application/htmltrust-content+json')).status(200).json(record);
  } catch (error) {
    console.error('Get content record error:', error);
    return problem(res, 500, 'Directory read failure', 'The directory could not read the content record', {
      type: 'https://htmltrust.org/errors/storage-failure',
    });
  }
};

/** Canonical v1 GET /content/:contentHash. */
exports.getContentRecordV1 = async (req, res) => {
  let contentHash;
  try {
    contentHash = assertContentHash(req.params.contentHash, 'contentHash');
  } catch (error) {
    return problem(res, 400, 'Invalid content hash', detailFor(error));
  }

  try {
    const record = await contentRecord(req, contentHash, { v1Only: true });
    if (!record) {
      return problem(res, 404, 'Content not found', 'No v1 content record exists for the requested hash', {
        contentHash,
      });
    }
    return res.type(negotiatedType(req, 'application/htmltrust-content+json')).status(200).json(record);
  } catch (error) {
    console.error('Get v1 content record error:', error);
    return problem(res, 500, 'Directory read failure', 'The directory could not read the content record', {
      type: 'https://htmltrust.org/errors/storage-failure',
    });
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
      .type(negotiatedType(req, 'application/htmltrust-content+json'))
      .json(record);
  } catch (error) {
    return problem(res, 400, 'Invalid content submission', detailFor(error));
  }
};

/**
 * Submit and re-verify an htmltrust-signature-v1 occurrence.
 *
 * This is the canonical POST /content handler. The `/api/content` handler
 * above remains the explicit pre-v1 compatibility endpoint.
 */
exports.submitContentV1 = async (req, res) => {
  let submission;
  try {
    submission = await validateV1ContentSubmission(req.body);
  } catch (error) {
    return problem(res, 400, 'Invalid content submission', detailFor(error), {
      type: 'https://htmltrust.org/errors/content-submission-invalid',
    });
  }

  try {
    const resolution = await resolveUsableKey(submission.keyid, { req, algorithm: submission.algorithm });
    if (!resolution.ok) {
      return problem(
        res,
        400,
        'Key resolution failed',
        `The submitted keyid could not be resolved to a usable key (${resolution.reason})`,
        {
          type: `https://htmltrust.org/errors/${resolution.reason}`,
          keyid: submission.keyid,
        },
      );
    }
    if (resolution.resolved.algorithm !== submission.algorithm) {
      return problem(
        res,
        400,
        'Algorithm mismatch',
        `The submission declares ${submission.algorithm} but the resolved key uses ${resolution.resolved.algorithm}`,
        { type: 'https://htmltrust.org/errors/algorithm-mismatch' },
      );
    }
    if (!verifySignature(
      submission.payload,
      submission.signature,
      resolution.resolved.publicKeyPem,
      submission.algorithm,
    )) {
      return problem(
        res,
        400,
        'Signature verification failed',
        'The submitted signature did not verify against the canonical signing payload.',
        {
          type: 'https://htmltrust.org/errors/signature-invalid',
          contentHash: submission.contentHash,
        },
      );
    }

    const localKey = resolution.resolved.key;
    const identity = {
      contentHash: submission.contentHash,
      profile: submission.profile,
      location: submission.location,
      keyid: submission.keyid,
    };
    let contentSignature = await ContentSignature.findOne(identity);
    const storedClaims = Object.fromEntries(
      submission.claims.map(({ name, content }) => [name, content]),
    );
    if (contentSignature) {
      contentSignature.algorithm = submission.algorithm;
      contentSignature.claimsHash = submission.claimsHash;
      contentSignature.signedAt = submission.signedAt;
      contentSignature.scope = submission.scope;
      contentSignature.sourceURL = submission.sourceURL;
      contentSignature.signature = submission.signature;
      contentSignature.claims = storedClaims;
      contentSignature.occurrences += 1;
      if (localKey) {
        contentSignature.authorId = localKey.authorId;
        contentSignature.keyId = localKey._id;
      }
      await contentSignature.save();
    } else {
      contentSignature = await ContentSignature.create({
        ...identity,
        algorithm: submission.algorithm,
        claimsHash: submission.claimsHash,
        signedAt: submission.signedAt,
        scope: submission.scope,
        sourceURL: submission.sourceURL,
        signature: submission.signature,
        claims: storedClaims,
        authorId: localKey && localKey.authorId,
        keyId: localKey && localKey._id,
      });
    }

    const sourceOrigin = new URL(submission.sourceURL).origin;
    await ContentOccurrence.findOneAndUpdate(
      { signatureId: contentSignature._id, url: submission.sourceURL },
      {
        signatureId: contentSignature._id,
        url: submission.sourceURL,
        domain: sourceOrigin,
        signatureValid: true,
        lastSeen: Date.now(),
      },
      { upsert: true, setDefaultsOnInsert: true },
    );

    const record = await contentRecord(req, submission.contentHash, { v1Only: true });
    return res
      .status(201)
      .location(`/content/${encodeURIComponent(submission.contentHash)}`)
      .type(negotiatedType(req, 'application/htmltrust-content+json'))
      .json(record);
  } catch (error) {
    console.error('Submit v1 content error:', error);
    return problem(res, 500, 'Content storage failed', detailFor(
      error,
      'The directory could not store the verified content record',
    ), {
      type: 'https://htmltrust.org/errors/content-storage-failed',
    });
  }
};

exports.listContentEndorsements = async (req, res) => {
  let contentHash;
  try {
    contentHash = assertContentHash(req.params.contentHash, 'contentHash');
  } catch (error) {
    return problem(res, 400, 'Invalid content hash', detailFor(error));
  }

  try {
    const endorsements = await Endorsement.find({
      $or: [{ endorsement: contentHash }, { contentHash }],
    }).sort({ createdAt: -1 });
    const { toEndorsementDocument } = require('./endorsementController');
    res
      .type(negotiatedType(req, 'application/htmltrust-endorsement+json'))
      .status(200)
      .json(endorsements.map(toEndorsementDocument));
  } catch (error) {
    console.error('List content endorsements error:', error);
    return problem(res, 500, 'Directory read failure', 'The directory could not read endorsements', {
      type: 'https://htmltrust.org/errors/storage-failure',
    });
  }
};
