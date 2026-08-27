const express = require("express");
const router = express.Router();
const {
  createVote,
  getVotes,
  deleteVote,
  getVoteStats,
} = require("../controllers/voteController");
const { protectWithGeneralApiKey } = require("../middleware/auth");
const { requireActorSignature } = require("../middleware/httpSignature");

// Votes move reputation, so the voter is the verified signer of the request
// when one is present; see voterIdentity() in the controller.
const authenticatedVoter = requireActorSignature({ fallback: protectWithGeneralApiKey });

// Routes
router.route("/").post(authenticatedVoter, createVote);

router.route("/stats/:targetType/:targetId").get(getVoteStats);

router.route("/:targetType/:targetId").get(getVotes);

router.route("/:voteId").delete(authenticatedVoter, deleteVote);

module.exports = router;
