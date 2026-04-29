const express = require('express');
const router = express.Router();
const {
  createEndorsement,
  listEndorsements,
  deleteEndorsement
} = require('../controllers/endorsementController');
const { protectWithGeneralApiKey } = require('../middleware/auth');

// Routes
router.route('/')
  .get(listEndorsements)
  .post(protectWithGeneralApiKey, createEndorsement);

router.route('/:id')
  .delete(protectWithGeneralApiKey, deleteEndorsement);

module.exports = router;
