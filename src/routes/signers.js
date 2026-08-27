const express = require('express');
const router = express.Router();
const { getSignerReputation } = require('../controllers/directoryController');

router.route('/:id/reputation')
  .get(getSignerReputation);

module.exports = router;
