const express = require('express');
const router = express.Router();
const {
  createEndorsement,
  listEndorsements,
  deleteEndorsement
} = require('../controllers/endorsementController');
const { protectWithGeneralApiKey } = require('../middleware/auth');
const { requireActorSignature } = require('../middleware/httpSignature');

// Routes
//
// Draft §9.8 requires POST endpoints to be authenticated with an RFC 9421
// HTTP Message Signature. The static API key remains as a fallback for the
// demo UI and the conformance suite, and is disabled in production.
router.route('/')
  .get(listEndorsements)
  .post(requireActorSignature({ fallback: protectWithGeneralApiKey }), createEndorsement);

// DELETE authorizes on the endorser's own key (or the admin key) inside the
// controller, so an unsigned request is passed through to be rejected there
// with the right diagnostic rather than being accepted by a shared secret.
router.route('/:id')
  .delete(requireActorSignature({ fallback: (req, res, next) => next() }), deleteEndorsement);

module.exports = router;
