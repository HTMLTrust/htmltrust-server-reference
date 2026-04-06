const express = require('express');
const router = express.Router();
const {
  createClaimType,
  getClaimTypes,
  getClaimType,
  updateClaimType,
  deleteClaimType
} = require('../controllers/claimController');
const {
  protectWithAdminApiKey
} = require('../middleware/auth');

// Routes
router.route('/')
  .post(protectWithAdminApiKey, createClaimType)
  .get(getClaimTypes);

router.route('/:claimId')
  .get(getClaimType)
  .put(protectWithAdminApiKey, updateClaimType)
  .delete(protectWithAdminApiKey, deleteClaimType);

module.exports = router;