const Author = require("../models/Author");
const Key = require("../models/Key");
const { generateKeyPair, generateApiKey } = require("../utils/crypto");

/**
 * @desc    Create a new author and key pair
 * @route   POST /api/authors
 * @access  Private (General API Key)
 */
exports.createAuthor = async (req, res) => {
  try {
    const { name, description, url, keyType, keyAlgorithm = "RSA" } = req.body;

    // Generate key pair
    const { publicKey, privateKey } = generateKeyPair(keyAlgorithm);

    // Generate author API key
    const apiKey = generateApiKey();

    // Create author
    const author = await Author.create({
      name,
      description,
      url,
      keyType,
      apiKey,
    });

    // Create key
    await Key.create({
      authorId: author._id,
      publicKey,
      privateKey,
      algorithm: keyAlgorithm,
    });

    // Return author details and API key (only returned once)
    res.status(201).json({
      author: {
        id: author._id,
        name: author.name,
        description: author.description,
        url: author.url,
        keyType: author.keyType,
        createdAt: author.createdAt,
        updatedAt: author.updatedAt,
      },
      authorApiKey: apiKey,
    });
  } catch (error) {
    console.error("Create author error:", error);
    res.status(400).json({
      code: "BAD_REQUEST",
      message: error.message,
    });
  }
};

/**
 * @desc    Get all authors
 * @route   GET /api/authors
 * @access  Private (General API Key)
 */
exports.getAuthors = async (req, res) => {
  try {
    const { name, keyType, page = 1, limit = 20 } = req.query;

    // Build query
    const query = {};
    if (name) query.name = { $regex: name, $options: "i" };
    if (keyType) query.keyType = keyType;

    // Pagination
    const skip = (parseInt(page) - 1) * parseInt(limit);

    // Execute query
    const authors = await Author.find(query)
      .skip(skip)
      .limit(parseInt(limit))
      .sort({ createdAt: -1 });

    // Get total count
    const total = await Author.countDocuments(query);

    res.status(200).json({
      authors,
      pagination: {
        total,
        pages: Math.ceil(total / parseInt(limit)),
        page: parseInt(page),
        limit: parseInt(limit),
      },
    });
  } catch (error) {
    console.error("Get authors error:", error);
    res.status(500).json({
      code: "SERVER_ERROR",
      message: error.message,
    });
  }
};

/**
 * @desc    Get a single author
 * @route   GET /api/authors/:authorId
 * @access  Public
 */
exports.getAuthor = async (req, res) => {
  try {
    const author = await Author.findById(req.params.authorId);

    if (!author) {
      return res.status(404).json({
        code: "NOT_FOUND",
        message: "Author not found",
      });
    }

    res.status(200).json(author);
  } catch (error) {
    console.error("Get author error:", error);
    res.status(500).json({
      code: "SERVER_ERROR",
      message: error.message,
    });
  }
};

/**
 * @desc    Update an author
 * @route   PUT /api/authors/:authorId
 * @access  Private (Author API Key)
 */
exports.updateAuthor = async (req, res) => {
  try {
    const { name, description, url } = req.body;

    // Find author
    let author = await Author.findById(req.params.authorId);

    if (!author) {
      return res.status(404).json({
        code: "NOT_FOUND",
        message: "Author not found",
      });
    }

    // Update fields
    if (name) author.name = name;
    if (description !== undefined) author.description = description;
    if (url !== undefined) author.url = url;

    // Save changes
    await author.save();

    res.status(200).json(author);
  } catch (error) {
    console.error("Update author error:", error);
    res.status(400).json({
      code: "BAD_REQUEST",
      message: error.message,
    });
  }
};

/**
 * @desc    Delete an author
 * @route   DELETE /api/authors/:authorId
 * @access  Private (Author API Key)
 */
exports.deleteAuthor = async (req, res) => {
  try {
    // Find author
    const author = await Author.findById(req.params.authorId);

    if (!author) {
      return res.status(404).json({
        code: "NOT_FOUND",
        message: "Author not found",
      });
    }

    // Delete associated keys
    await Key.deleteMany({ authorId: author._id });

    // Delete author
    await Author.deleteOne({ _id: author._id });

    res.status(204).send();
  } catch (error) {
    console.error("Delete author error:", error);
    res.status(500).json({
      code: "SERVER_ERROR",
      message: error.message,
    });
  }
};

/**
 * @desc    Get author's public key
 * @route   GET /api/authors/:authorId/public-key
 * @access  Public
 */
exports.getAuthorPublicKey = async (req, res) => {
  try {
    // Find key
    const key = await Key.findOne({ authorId: req.params.authorId });

    if (!key) {
      return res.status(404).json({
        code: "NOT_FOUND",
        message: "Public key not found",
      });
    }

    res.status(200).json({
      id: key._id,
      authorId: key.authorId,
      key: key.publicKey,
      algorithm: key.algorithm,
      createdAt: key.createdAt,
      expiresAt: key.expiresAt,
    });
  } catch (error) {
    console.error("Get public key error:", error);
    res.status(500).json({
      code: "SERVER_ERROR",
      message: error.message,
    });
  }
};
