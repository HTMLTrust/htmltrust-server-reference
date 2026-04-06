const Claim = require("../models/Claim");

/**
 * @desc    Create a new claim type
 * @route   POST /api/claims
 * @access  Private (Admin API Key)
 */
exports.createClaimType = async (req, res) => {
  try {
    const { name, description, possibleValues } = req.body;

    // Check if claim type already exists
    const existingClaim = await Claim.findOne({ name });

    if (existingClaim) {
      return res.status(400).json({
        code: "BAD_REQUEST",
        message: "Claim type with this name already exists",
      });
    }

    // Create claim type
    const claim = await Claim.create({
      name,
      description,
      possibleValues,
    });

    res.status(201).json(claim);
  } catch (error) {
    console.error("Create claim type error:", error);
    res.status(400).json({
      code: "BAD_REQUEST",
      message: error.message,
    });
  }
};

/**
 * @desc    Get all claim types
 * @route   GET /api/claims
 * @access  Public
 */
exports.getClaimTypes = async (req, res) => {
  try {
    const { page = 1, limit = 20 } = req.query;

    // Pagination
    const skip = (parseInt(page) - 1) * parseInt(limit);

    // Execute query
    const claims = await Claim.find()
      .skip(skip)
      .limit(parseInt(limit))
      .sort({ name: 1 });

    // Get total count
    const total = await Claim.countDocuments();

    res.status(200).json({
      claims,
      pagination: {
        total,
        pages: Math.ceil(total / parseInt(limit)),
        page: parseInt(page),
        limit: parseInt(limit),
      },
    });
  } catch (error) {
    console.error("Get claim types error:", error);
    res.status(500).json({
      code: "SERVER_ERROR",
      message: error.message,
    });
  }
};

/**
 * @desc    Get a single claim type
 * @route   GET /api/claims/:claimId
 * @access  Public
 */
exports.getClaimType = async (req, res) => {
  try {
    const claim = await Claim.findById(req.params.claimId);

    if (!claim) {
      return res.status(404).json({
        code: "NOT_FOUND",
        message: "Claim type not found",
      });
    }

    res.status(200).json(claim);
  } catch (error) {
    console.error("Get claim type error:", error);
    res.status(500).json({
      code: "SERVER_ERROR",
      message: error.message,
    });
  }
};

/**
 * @desc    Update a claim type
 * @route   PUT /api/claims/:claimId
 * @access  Private (Admin API Key)
 */
exports.updateClaimType = async (req, res) => {
  try {
    const { description, possibleValues } = req.body;

    // Find claim type
    let claim = await Claim.findById(req.params.claimId);

    if (!claim) {
      return res.status(404).json({
        code: "NOT_FOUND",
        message: "Claim type not found",
      });
    }

    // Update fields
    if (description !== undefined) claim.description = description;
    if (possibleValues !== undefined) claim.possibleValues = possibleValues;

    // Save changes
    await claim.save();

    res.status(200).json(claim);
  } catch (error) {
    console.error("Update claim type error:", error);
    res.status(400).json({
      code: "BAD_REQUEST",
      message: error.message,
    });
  }
};

/**
 * @desc    Delete a claim type
 * @route   DELETE /api/claims/:claimId
 * @access  Private (Admin API Key)
 */
exports.deleteClaimType = async (req, res) => {
  try {
    // Find claim type
    const claim = await Claim.findById(req.params.claimId);

    if (!claim) {
      return res.status(404).json({
        code: "NOT_FOUND",
        message: "Claim type not found",
      });
    }

    // Delete claim type
    await Claim.deleteOne({ _id: claim._id });

    res.status(204).send();
  } catch (error) {
    console.error("Delete claim type error:", error);
    res.status(500).json({
      code: "SERVER_ERROR",
      message: error.message,
    });
  }
};
