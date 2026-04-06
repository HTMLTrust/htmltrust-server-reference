const express = require('express');
const router = express.Router();
const {
  createAuthor,
  getAuthors,
  getAuthor,
  updateAuthor,
  deleteAuthor,
  getAuthorPublicKey
} = require('../controllers/authorController');
const {
  protectWithGeneralApiKey,
  protectWithAuthorApiKey
} = require('../middleware/auth');

// Routes
router.route('/')
  .post(protectWithGeneralApiKey, createAuthor)
  .get(protectWithGeneralApiKey, getAuthors);

router.route('/:authorId')
  .get(getAuthor)
  .put(protectWithAuthorApiKey, updateAuthor)
  .delete(protectWithAuthorApiKey, deleteAuthor);

router.route('/:authorId/public-key')
  .get(getAuthorPublicKey);

module.exports = router;