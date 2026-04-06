const express = require('express');
const router = express.Router();
const {
  searchPublicKeys,
  getKeyReputation,
  reportKey,
  searchSignedContent,
  findContentOccurrences,
  reportContentMisuse
} = require('../controllers/directoryController');
const {
  protectWithGeneralApiKey
} = require('../middleware/auth');

// Key routes
router.route('/keys')
  .get(searchPublicKeys);

router.route('/keys/:keyId/reputation')
  .get(getKeyReputation);

router.route('/keys/:keyId/report')
  .post(protectWithGeneralApiKey, reportKey);

// Content routes
router.route('/content')
  .get(searchSignedContent);

router.route('/content/:contentHash/occurrences')
  .get(findContentOccurrences);

router.route('/content/report')
  .post(protectWithGeneralApiKey, reportContentMisuse);

module.exports = router;