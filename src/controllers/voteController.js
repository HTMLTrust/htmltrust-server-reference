const Vote = require("../models/Vote");
const Author = require("../models/Author");
const Key = require("../models/Key");
const ContentSignature = require("../models/ContentSignature");
const { detailFor, problem } = require("../utils/htmltrustProtocol");

/**
 * The identity a vote belongs to.
 *
 * Votes move a key's trust score, so who cast one has to be established by
 * the request rather than asserted in its body. A caller that authenticated
 * with an RFC 9421 signature votes as the key it signed with. A caller using
 * the shared demo API key has no distinguishable identity, so every such
 * caller collapses onto a single voter id — which, combined with the unique
 * { userId, targetType, targetId } index, means the shared key is worth
 * exactly one vote per target instead of unlimited ballot stuffing.
 */
const voterIdentity = (req) => {
  if (req.htmltrustActor) return `key:${req.htmltrustActor.keyid}`;
  if (req.author) return `author:${req.author._id}`;
  return "shared-api-key";
};

/**
 * @desc    Vote on an author or content
 * @route   POST /api/votes
 * @access  Private (General API Key)
 */
exports.createVote = async (req, res) => {
  try {
    const { targetType, targetId, voteType, reason } = req.body;
    const userId = voterIdentity(req);

    // Validate target exists
    let target;
    if (targetType === "AUTHOR") {
      target = await Author.findById(targetId);
    } else if (targetType === "CONTENT") {
      target = await ContentSignature.findById(targetId);
    }

    if (!target) {
      return res.status(404).json({
        code: "NOT_FOUND",
        message: `${targetType.toLowerCase()} not found`,
      });
    }

    // Check if user has already voted on this target
    let vote = await Vote.findOne({
      userId,
      targetType,
      targetId,
    });

    if (vote) {
      // Update existing vote
      vote.voteType = voteType;
      if (reason !== undefined) vote.reason = reason;
      await vote.save();
    } else {
      // Create new vote
      vote = await Vote.create({
        userId,
        targetType,
        targetId,
        voteType,
        reason,
      });
    }

    // Update trust score based on vote
    if (targetType === "AUTHOR") {
      // Find author's key
      const key = await Key.findOne({ authorId: targetId });

      if (key) {
        // Simple trust score adjustment - in a real system, you would have a more sophisticated algorithm
        if (voteType === "TRUST") {
          key.trustScore = Math.min(1, key.trustScore + 0.01);
        } else {
          key.trustScore = Math.max(0, key.trustScore - 0.01);
        }

        await key.save();
      }
    }

    res.status(201).json(vote);
  } catch (error) {
    console.error("Create vote error:", error);
    res.status(400).json({
      code: "BAD_REQUEST",
      message: detailFor(error),
    });
  }
};

/**
 * @desc    Get votes for a target
 * @route   GET /api/votes/:targetType/:targetId
 * @access  Public
 */
exports.getVotes = async (req, res) => {
  try {
    const { targetType, targetId } = req.params;
    const { page = 1, limit = 20 } = req.query;

    // Validate target exists
    let target;
    if (targetType === "AUTHOR") {
      target = await Author.findById(targetId);
    } else if (targetType === "CONTENT") {
      target = await ContentSignature.findById(targetId);
    }

    if (!target) {
      return res.status(404).json({
        code: "NOT_FOUND",
        message: `${targetType.toLowerCase()} not found`,
      });
    }

    // Pagination
    const skip = (parseInt(page) - 1) * parseInt(limit);

    // Get votes
    const votes = await Vote.find({
      targetType,
      targetId,
    })
      .skip(skip)
      .limit(parseInt(limit))
      .sort({ createdAt: -1 });

    // Get vote counts
    const trustCount = await Vote.countDocuments({
      targetType,
      targetId,
      voteType: "TRUST",
    });

    const distrustCount = await Vote.countDocuments({
      targetType,
      targetId,
      voteType: "DISTRUST",
    });

    // Get total count
    const total = await Vote.countDocuments({
      targetType,
      targetId,
    });

    res.status(200).json({
      votes,
      counts: {
        trust: trustCount,
        distrust: distrustCount,
        total,
      },
      pagination: {
        total,
        pages: Math.ceil(total / parseInt(limit)),
        page: parseInt(page),
        limit: parseInt(limit),
      },
    });
  } catch (error) {
    console.error("Get votes error:", error);
    res.status(500).json({
      code: "SERVER_ERROR",
      message: detailFor(error),
    });
  }
};

/**
 * @desc    Delete a vote
 * @route   DELETE /api/votes/:voteId
 * @access  Private (General API Key)
 */
exports.deleteVote = async (req, res) => {
  try {
    const vote = await Vote.findById(req.params.voteId);

    if (!vote) {
      return res.status(404).json({
        code: "NOT_FOUND",
        message: "Vote not found",
      });
    }

    // Ownership is derived from the authenticated request, not from a
    // caller-supplied body field: trusting `req.body.userId` let any caller
    // delete any vote simply by naming its owner.
    if (voterIdentity(req) !== vote.userId) {
      return problem(res, 403, "Forbidden", "Not authorized to delete this vote", {
        type: "https://htmltrust.org/errors/forbidden",
      });
    }

    await Vote.deleteOne({ _id: vote._id });

    // Update trust score based on removed vote
    if (vote.targetType === "AUTHOR") {
      // Find author's key
      const key = await Key.findOne({ authorId: vote.targetId });

      if (key) {
        // Simple trust score adjustment - in a real system, you would have a more sophisticated algorithm
        if (vote.voteType === "TRUST") {
          key.trustScore = Math.max(0, key.trustScore - 0.01);
        } else {
          key.trustScore = Math.min(1, key.trustScore + 0.01);
        }

        await key.save();
      }
    }

    res.status(204).send();
  } catch (error) {
    console.error("Delete vote error:", error);
    res.status(500).json({
      code: "SERVER_ERROR",
      message: detailFor(error),
    });
  }
};

/**
 * @desc    Get vote statistics
 * @route   GET /api/votes/stats/:targetType/:targetId
 * @access  Public
 */
exports.getVoteStats = async (req, res) => {
  try {
    const { targetType, targetId } = req.params;

    // Validate target exists
    let target;
    if (targetType === "AUTHOR") {
      target = await Author.findById(targetId);
    } else if (targetType === "CONTENT") {
      target = await ContentSignature.findById(targetId);
    }

    if (!target) {
      return res.status(404).json({
        code: "NOT_FOUND",
        message: `${targetType.toLowerCase()} not found`,
      });
    }

    // Get vote counts
    const trustCount = await Vote.countDocuments({
      targetType,
      targetId,
      voteType: "TRUST",
    });

    const distrustCount = await Vote.countDocuments({
      targetType,
      targetId,
      voteType: "DISTRUST",
    });

    // Calculate trust score
    const totalVotes = trustCount + distrustCount;
    const trustScore = totalVotes > 0 ? trustCount / totalVotes : 0.5;

    res.status(200).json({
      targetType,
      targetId,
      trustCount,
      distrustCount,
      totalVotes,
      trustScore,
    });
  } catch (error) {
    console.error("Get vote stats error:", error);
    res.status(500).json({
      code: "SERVER_ERROR",
      message: detailFor(error),
    });
  }
};
