const SignerVote = require('../models/SignerVote');
const { problem } = require('../utils/htmltrustProtocol');

const MAX_SIGNER_ID_LENGTH = 2048;
const MAX_REASON_LENGTH = 4096;

/**
 * Use the verified HTTP-signature key as the voter identity. The shared API
 * key fallback remains available for the demo deployment and intentionally
 * collapses those submissions to one voter, as the legacy vote API does.
 */
function voterIdentity(req) {
  if (req.htmltrustActor?.keyid) return `key:${req.htmltrustActor.keyid}`;
  if (req.author?._id) return `author:${req.author._id}`;
  return 'shared-api-key';
}

function validateSignerId(value) {
  if (typeof value !== 'string' || value.length === 0 || value.length > MAX_SIGNER_ID_LENGTH) {
    return 'signerId must be between 1 and 2048 characters';
  }
  if (value.trim() !== value) return 'signerId must not have surrounding whitespace';
  if (/[\u0000-\u001f\u007f]/.test(value)) {
    return 'signerId contains a control character';
  }
  return null;
}

/** POST /api/directory/signer-votes */
exports.submitSignerVote = async (req, res) => {
  try {
    if (!req.body || typeof req.body !== 'object' || Array.isArray(req.body)) {
      return problem(res, 400, 'Invalid request body', 'The request body must be a JSON object');
    }
    const unknownFields = Object.keys(req.body).filter(
      (field) => !['signerId', 'voteType', 'reason'].includes(field),
    );
    if (unknownFields.length > 0) {
      return problem(res, 400, 'Invalid request body', 'Only signerId, voteType, and reason are accepted');
    }
    const { signerId, voteType, reason } = req.body || {};
    const signerError = validateSignerId(signerId);
    if (signerError) return problem(res, 400, 'Invalid signer id', signerError);
    if (voteType !== 'TRUST' && voteType !== 'DISTRUST') {
      return problem(res, 400, 'Invalid vote type', 'voteType must be TRUST or DISTRUST');
    }
    if (reason !== undefined && (typeof reason !== 'string' || reason.length > MAX_REASON_LENGTH)) {
      return problem(res, 400, 'Invalid reason', 'reason must be a string of at most 4096 characters');
    }

    const voterId = voterIdentity(req);
    const filter = { voterId, signerId };
    const update = {
      $set: { voteType, ...(reason === undefined ? {} : { reason }) },
      $setOnInsert: { voterId, signerId },
    };
    let previous;
    try {
      previous = await SignerVote.findOneAndUpdate(filter, update, {
        new: false,
        upsert: true,
        setDefaultsOnInsert: true,
      });
    } catch (error) {
      // Concurrent first votes can race at the unique index. Retry as a plain
      // update so both callers complete and the last write becomes current.
      if (error?.code !== 11000) throw error;
      previous = await SignerVote.findOneAndUpdate(filter, update, { new: false });
    }
    const vote = await SignerVote.findOne(filter);
    if (!vote) throw new Error('signer vote could not be stored');
    const previousVoteType = previous?.voteType || null;

    return res.status(previousVoteType ? 200 : 201).json({
      voteId: String(vote._id),
      voterId,
      signerId,
      voteType,
      previousVoteType,
      updatedAt: vote.updatedAt,
    });
  } catch (error) {
    console.error('Submit signer vote error:', error);
    return problem(res, 500, 'Directory write failure', 'The directory could not store the signer vote', {
      type: 'https://htmltrust.org/errors/storage-failure',
    });
  }
};

exports.voterIdentity = voterIdentity;
