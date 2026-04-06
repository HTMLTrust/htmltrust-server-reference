const express = require('express');
const router = express.Router();
const {
  signContent,
  verifyContent,
  registerOccurrence
} = require('../controllers/contentController');
const {
  protectWithAuthorApiKey,
  protectWithGeneralApiKey
} = require('../middleware/auth');

// Routes
router.route('/sign')
  .post(protectWithAuthorApiKey, signContent);

router.route('/verify')
  .post(verifyContent);

router.route('/occurrences')
  .post(protectWithGeneralApiKey, registerOccurrence);

module.exports = router;