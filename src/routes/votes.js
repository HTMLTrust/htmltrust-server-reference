const express = require("express");
const router = express.Router();
const {
  createVote,
  getVotes,
  deleteVote,
  getVoteStats,
} = require("../controllers/voteController");
const { protectWithGeneralApiKey } = require("../middleware/auth");

// Routes
router.route("/").post(protectWithGeneralApiKey, createVote);

router.route("/stats/:targetType/:targetId").get(getVoteStats);

router.route("/:targetType/:targetId").get(getVotes);

router.route("/:voteId").delete(protectWithGeneralApiKey, deleteVote);

module.exports = router;
