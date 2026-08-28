const express = require('express');
const router = express.Router();
const {
  searchPublicKeys,
  getKeyReputation,
  reportKey,
  reportSigner,
  searchSignedContent,
  findContentOccurrences,
  reportContentMisuse
} = require('../controllers/directoryController');
const { submitSignerVote } = require('../controllers/signerVoteController');
const {
  protectWithGeneralApiKey,
} = require('../middleware/auth');
const { requireActorSignature } = require('../middleware/httpSignature');

const authenticatedVoter = requireActorSignature({ fallback: protectWithGeneralApiKey });

// Key routes
router.route('/keys')
  .get(searchPublicKeys);

router.route('/keys/:keyId/reputation')
  .get(getKeyReputation);

router.route('/keys/:keyId/report')
  .post(protectWithGeneralApiKey, reportKey);

// A directory can record an opinion about a keyid published by another
// directory. The body keeps the exact foreign signer identifier and avoids
// relying on encoded slashes in an Express path parameter.
router.route('/signer-reports')
  .post(protectWithGeneralApiKey, reportSigner);

// A signer vote is keyed by the authenticated HTTP-signature actor when one
// is present. The API-key fallback is retained for the local demo deployment.
router.route('/signer-votes')
  .post(authenticatedVoter, submitSignerVote);

// Content routes
router.route('/content')
  .get(searchSignedContent);

router.route('/content/:contentHash/occurrences')
  .get(findContentOccurrences);

router.route('/content/report')
  .post(protectWithGeneralApiKey, reportContentMisuse);

module.exports = router;
