const express = require('express');
const router = express.Router();
const { getKeyDocument } = require('../controllers/directoryController');

router.route('/:id')
  .get(getKeyDocument);

module.exports = router;
