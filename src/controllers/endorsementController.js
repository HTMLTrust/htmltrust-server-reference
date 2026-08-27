const crypto = require('crypto');
const Endorsement = require('../models/Endorsement');
const { verifySignature } = require('../utils/crypto');
const {
  assertContentHash,
  assertRfc3339Utc,
  assertSignatureAlgorithm,
  canonicalizeEndorsement,
  decodeCanonicalBase64,
  detailFor,
  invalid,
  problem,
} = require('../utils/htmltrustProtocol');
const { canonicalizeJcs } = require('../utils/jcs');
const { resolveUsableKey, sameKeyMaterial } = require('../utils/keyResolution');
const { hasAdminApiKey } = require('../middleware/auth');

/**
 * Return the stored endorsement document exactly as it was submitted.
 *
 * Draft §9.5: "The directory MUST NOT alter the endorsement payloads in a
 * manner that invalidates the endorser's signature", and §10.1 requires
 * unrecognised members to be preserved and included in the signed payload.
 * Any member the directory adds — an `_id`, a `createdAt`, a `contentHash`
 * alias — becomes part of JCS(document minus signature) for anyone who
 * recomputes it, and the signature no longer verifies.
 *
 * Server-side bookkeeping is therefore kept out of the body entirely: the
 * identifier of a newly stored endorsement is returned in the `Location`
 * header of the 201 response.
 */
const toEndorsementDocument = (endorsement) => {
  if (endorsement.document && typeof endorsement.document === 'object') {
    return endorsement.document;
  }
  // Rows written before structured documents were stored: reconstruct the
  // draft shape from the indexed columns.
  const document = {
    endorser: endorsement.endorser,
    endorsement: endorsement.endorsement || endorsement.contentHash,
    algorithm: endorsement.algorithm,
    timestamp: endorsement.timestamp,
    signature: endorsement.signature,
  };
  if (endorsement.claim) document.claim = endorsement.claim;
  if (endorsement.expires) document.expires = endorsement.expires;
  if (endorsement.revokedBy) document.revokedBy = endorsement.revokedBy;
  return document;
};

/**
 * Validate a submitted endorsement document against draft §10.1 WITHOUT
 * changing it. The returned object is the same object graph that will be
 * canonicalized, verified, and stored, so nothing may be injected into it:
 * every added member changes the signing payload.
 */
const validateEndorsementDocument = (body) => {
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    throw invalid('The endorsement document must be a JSON object');
  }
  const document = { ...body };

  // `rawBlob` is a legacy compatibility field that was never part of the
  // signed document; strip it before verification so old clients that still
  // send it do not fail, and keep it out of storage.
  delete document.rawBlob;

  for (const field of ['endorser', 'endorsement', 'signature', 'timestamp']) {
    if (typeof document[field] !== 'string' || document[field].length === 0) {
      throw invalid(`${field} is required`);
    }
  }
  if (typeof document.algorithm !== 'string' || document.algorithm.length === 0) {
    throw invalid('algorithm is required');
  }

  assertContentHash(document.endorsement, 'endorsement');
  assertSignatureAlgorithm(document.algorithm);
  assertRfc3339Utc(document.timestamp, 'timestamp');
  decodeCanonicalBase64(document.signature, 'signature');
  if (document.expires !== undefined) assertRfc3339Utc(document.expires, 'expires');
  if (document.revokedBy !== undefined) assertContentHash(document.revokedBy, 'revokedBy');
  if (document.claim !== undefined && typeof document.claim !== 'string') {
    throw invalid('claim must be a string');
  }

  return document;
};

const documentHashFor = (document) =>
  `sha256:${crypto.createHash('sha256').update(canonicalizeJcs(document)).digest('base64').replace(/=+$/, '')}`;

/**
 * Verify the endorser's signature over JCS(document minus `signature`), per
 * draft §10.2.
 *
 * Verification is mandatory. A directory that stores endorsements it cannot
 * verify is a publication channel for forged attestations: anyone can claim
 * any endorser's identity, and every consumer that trusts the directory's
 * index (rather than re-verifying) inherits the forgery. Draft §9.7 states
 * the requirement directly — the directory MUST verify the endorser's
 * signature, and invalid signatures MUST be rejected with 400.
 *
 * @returns {Promise<{ok: true} | {ok: false, status: number, title: string, detail: string, type?: string}>}
 */
const verifyEndorsementSignature = async (document, req) => {
  const resolution = await resolveUsableKey(document.endorser, { req });
  if (!resolution.ok) {
    return {
      ok: false,
      status: 400,
      title: 'Key resolution failed',
      detail:
        resolution.reason === 'key-resolution-failed'
          ? 'The endorser keyid could not be resolved to a public key this directory can verify against'
          : `The endorser key is not usable (${resolution.reason})`,
      type: `https://htmltrust.org/errors/${resolution.reason}`,
      resolved: resolution.resolved,
    };
  }

  const { resolved } = resolution;
  if (resolved.algorithm !== document.algorithm) {
    return {
      ok: false,
      status: 400,
      title: 'Algorithm mismatch',
      detail: `The endorsement declares ${document.algorithm} but the resolved key is ${resolved.algorithm}`,
      type: 'https://htmltrust.org/errors/algorithm-mismatch',
    };
  }

  const payload = canonicalizeEndorsement(document);
  if (!verifySignature(payload, document.signature, resolved.publicKeyPem, resolved.algorithm)) {
    return {
      ok: false,
      status: 400,
      title: 'Signature verification failed',
      detail: 'The endorsement signature did not verify against the canonical JSON payload.',
      type: 'https://htmltrust.org/errors/signature-invalid',
    };
  }

  return { ok: true, resolved };
};

/**
 * @desc    Create an endorsement
 * @route   POST /api/endorsements
 * @access  Private (RFC 9421 signature, or the demo API key scheme)
 *
 * Request body is an endorsement document per draft §10.1:
 *   - endorser:    string (keyid resolvable per §8)
 *   - endorsement: string (content hash, e.g. "sha256:...")
 *   - signature:   string (unpadded Base64 over JCS(document minus signature))
 *   - algorithm:   string (§7.1 identifier)
 *   - timestamp:   string (RFC 3339 UTC)
 *   - claim, expires, revokedBy and any additional members: optional, stored
 *     and served verbatim.
 */
exports.createEndorsement = async (req, res) => {
  let document;
  try {
    document = validateEndorsementDocument(req.body);
  } catch (error) {
    return problem(res, 400, 'Invalid endorsement', detailFor(error, 'The endorsement document is not valid'), {
      type: 'https://htmltrust.org/errors/endorsement-invalid',
    });
  }

  try {
    const verification = await verifyEndorsementSignature(document, req);
    if (!verification.ok) {
      return problem(res, verification.status, verification.title, verification.detail, {
        type: verification.type,
        contentHash: document.endorsement,
      });
    }

    const documentHash = documentHashFor(document);

    // Append-only with idempotent resubmission. A second, different document
    // from the same endorser for the same content hash (a revocation, an
    // updated claim) is stored alongside the first: draft §10.3 requires a
    // directory holding both to serve both.
    let stored = await Endorsement.findOne({ documentHash });
    let created = false;
    if (!stored) {
      stored = await Endorsement.create({
        endorser: document.endorser,
        endorsement: document.endorsement,
        contentHash: document.endorsement,
        signature: document.signature,
        timestamp: document.timestamp,
        algorithm: document.algorithm,
        claim: document.claim,
        expires: document.expires,
        revokedBy: document.revokedBy,
        document,
        documentHash,
      });
      created = true;
    }

    return res
      .status(created ? 201 : 200)
      .location(`/api/endorsements/${stored._id}`)
      .type('application/htmltrust-endorsement+json')
      .json(toEndorsementDocument(stored));
  } catch (error) {
    console.error('Create endorsement error:', error);
    return problem(res, 400, 'Invalid endorsement', detailFor(error, 'The endorsement could not be stored'), {
      type: 'https://htmltrust.org/errors/endorsement-invalid',
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
    const contentHash = req.query['content-hash'] || req.query.contentHash || req.query.endorsement;

    if (!contentHash) {
      return problem(res, 400, 'Invalid request', 'content-hash query parameter is required');
    }

    const endorsementHash = assertContentHash(String(contentHash), 'content-hash');
    const endorsements = await Endorsement.find({
      $or: [{ endorsement: endorsementHash }, { contentHash: endorsementHash }]
    }).sort({ createdAt: -1 });

    return res
      .type('application/htmltrust-endorsement+json')
      .status(200)
      .json(endorsements.map(toEndorsementDocument));
  } catch (error) {
    console.error('List endorsements error:', error);
    return problem(res, 400, 'Invalid content hash', detailFor(error, 'The content-hash parameter is not valid'));
  }
};

exports.toEndorsementDocument = toEndorsementDocument;

/**
 * @desc    Delete an endorsement
 * @route   DELETE /api/endorsements/:id
 * @access  The endorser (RFC 9421 signature) or the directory operator
 *
 * Deletion is a compatibility operation; the protocol's own mechanism for
 * withdrawing an endorsement is a revocation endorsement (draft §10.3), which
 * is served alongside the original rather than replacing it.
 *
 * Authorization is by key, not by API key: the caller must sign the DELETE
 * with the endorsement's own endorser key (compared on the resolved key
 * material, so an alias keyid still matches), or present the directory admin
 * key for an operator takedown. Any holder of the shared submission key being
 * able to delete anyone's endorsements is a censorship primitive.
 */
exports.deleteEndorsement = async (req, res) => {
  try {
    const endorsement = await Endorsement.findById(req.params.id);

    if (!endorsement) {
      return problem(res, 404, 'Endorsement not found', 'No endorsement exists with the requested id');
    }

    if (!hasAdminApiKey(req)) {
      const actor = req.htmltrustActor;
      if (!actor) {
        res.set('WWW-Authenticate', 'Signature realm="htmltrust-directory"');
        return problem(
          res,
          401,
          'Unauthorized',
          'Deleting an endorsement requires an RFC 9421 signature from the endorser key, or the directory admin key',
          { type: 'https://htmltrust.org/errors/unauthorized' },
        );
      }

      const endorserKey = await resolveUsableKey(endorsement.endorser, { req });
      const sameKeyid = actor.keyid === endorsement.endorser;
      const sameMaterial =
        endorserKey.ok && sameKeyMaterial(actor.resolved.publicKeyPem, endorserKey.resolved.publicKeyPem);
      if (!sameKeyid && !sameMaterial) {
        return problem(res, 403, 'Forbidden', 'Only the endorser may delete this endorsement', {
          type: 'https://htmltrust.org/errors/forbidden',
        });
      }
    }

    await Endorsement.deleteOne({ _id: endorsement._id });

    return res.status(204).send();
  } catch (error) {
    console.error('Delete endorsement error:', error);
    return problem(res, 400, 'Invalid request', detailFor(error, 'The endorsement could not be deleted'));
  }
};
