const express = require('express');
const router = express.Router();
const {
  signContent,
  verifyContent,
  registerOccurrence,
  getContentRecord,
  submitContent,
  listContentEndorsements
} = require('../controllers/contentController');
const {
  protectWithAuthorApiKey,
  protectWithGeneralApiKey
} = require('../middleware/auth');
const { requireActorSignature } = require('../middleware/httpSignature');

// Routes
router.route('/sign')
  .post(protectWithAuthorApiKey, signContent);

router.route('/verify')
  .post(verifyContent);

router.route('/occurrences')
  .post(protectWithGeneralApiKey, registerOccurrence);

// Draft §9.4/§9.8: submissions are authenticated with an RFC 9421 HTTP
// Message Signature from a resolvable key. The static API key remains as a
// fallback for the demo UI and the conformance suite, and is disabled in
// production.
router.route('/')
  .post(requireActorSignature({ fallback: protectWithGeneralApiKey }), submitContent);

router.route('/:contentHash/endorsements')
  .get(listContentEndorsements);

router.route('/:contentHash')
  .get(getContentRecord);

module.exports = router;
