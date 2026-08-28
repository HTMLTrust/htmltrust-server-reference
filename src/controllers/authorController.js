const crypto = require("crypto");
const Author = require("../models/Author");
const Key = require("../models/Key");
const { generateKeyPair, generateApiKey } = require("../utils/crypto");
const { detailFor, invalid, problem, safeSearchRegex } = require("../utils/htmltrustProtocol");
const { hashApiKey } = require("../utils/apiKeys");

/**
 * @desc    Create a new author and key pair
 * @route   POST /api/authors
 * @access  Private (General API Key)
 */
exports.createAuthor = async (req, res) => {
  try {
    const { name, description, url, keyType, keyAlgorithm = "ed25519" } = req.body;

    // An author MAY register a public key it already holds, in which case the
    // directory never sees the private half. Otherwise the directory acts as
    // the convenience registry described in draft §9.6 and generates the pair.
    let publicKey = req.body.publicKey;
    let privateKey;
    if (publicKey) {
      if (typeof publicKey !== "string" || !publicKey.includes("BEGIN PUBLIC KEY")) {
        throw invalid("publicKey must be an SPKI PEM public key");
      }
      try {
        crypto.createPublicKey(publicKey);
      } catch {
        throw invalid("publicKey is not a readable SPKI PEM public key");
      }
    } else {
      ({ publicKey, privateKey } = generateKeyPair(keyAlgorithm));
    }

    // Generate author API key. Only the HMAC of the key is persisted; the key
    // itself is returned once here and cannot be recovered afterwards.
    const apiKey = generateApiKey();

    // Create author
    const author = await Author.create({
      name,
      description,
      url,
      keyType,
      apiKeyHash: hashApiKey(apiKey),
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
      message: detailFor(error, "The author could not be created"),
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

    // Build query. `name` is caller input: escaped, length-capped, and
    // anchored so it cannot become regular-expression syntax evaluated inside
    // the database (NoSQL injection / ReDoS).
    const query = {};
    if (name) query.name = safeSearchRegex(name, "name");
    if (keyType) query.keyType = String(keyType);

    // Pagination, clamped so one request cannot page the whole collection.
    const pageNumber = Math.max(1, parseInt(page, 10) || 1);
    const pageSize = Math.min(100, Math.max(1, parseInt(limit, 10) || 20));
    const skip = (pageNumber - 1) * pageSize;

    // Execute query
    const authors = await Author.find(query)
      .skip(skip)
      .limit(pageSize)
      .sort({ createdAt: -1 });

    // Get total count
    const total = await Author.countDocuments(query);

    res.status(200).json({
      authors,
      pagination: {
        total,
        pages: Math.ceil(total / pageSize),
        page: pageNumber,
        limit: pageSize,
      },
    });
  } catch (error) {
    if (error.expose) {
      return problem(res, 400, "Invalid query", error.message);
    }
    console.error("Get authors error:", error);
    res.status(500).json({
      code: "SERVER_ERROR",
      message: detailFor(error),
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
      message: detailFor(error),
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
      message: detailFor(error),
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
      message: detailFor(error),
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
      // Expose the opaque protocol identifier. Keep the Mongo ObjectId in the
      // compatibility storage model, but never make it the new key URL id.
      id: key.publicId || key._id,
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
      message: detailFor(error),
    });
  }
};
