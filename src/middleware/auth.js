const Author = require("../models/Author");

/**
 * Middleware to protect routes that require general API key authentication
 */
const protectWithGeneralApiKey = async (req, res, next) => {
  try {
    const apiKey = req.header("X-API-KEY");

    if (!apiKey) {
      return res.status(401).json({
        code: "UNAUTHORIZED",
        message: "No API key provided",
      });
    }

    // In a real implementation, you would validate the API key against a database
    // For this example, we'll use a simple check against an environment variable
    if (apiKey !== process.env.GENERAL_API_KEY) {
      return res.status(401).json({
        code: "UNAUTHORIZED",
        message: "Invalid API key",
      });
    }

    next();
  } catch (error) {
    console.error("Auth error:", error);
    res.status(401).json({
      code: "UNAUTHORIZED",
      message: "Authentication failed",
    });
  }
};

/**
 * Middleware to protect routes that require author-specific API key authentication
 */
const protectWithAuthorApiKey = async (req, res, next) => {
  try {
    const apiKey = req.header("X-AUTHOR-API-KEY");

    if (!apiKey) {
      return res.status(401).json({
        code: "UNAUTHORIZED",
        message: "No author API key provided",
      });
    }

    // Find the author with this API key
    const author = await Author.findOne({ apiKey }).select("+apiKey");

    if (!author) {
      return res.status(401).json({
        code: "UNAUTHORIZED",
        message: "Invalid author API key",
      });
    }

    // Check if the author ID in the URL matches the authenticated author
    if (req.params.authorId && req.params.authorId !== author._id.toString()) {
      return res.status(403).json({
        code: "FORBIDDEN",
        message: "API key does not match author",
      });
    }

    // Add author to request object
    req.author = author;

    next();
  } catch (error) {
    console.error("Auth error:", error);
    res.status(401).json({
      code: "UNAUTHORIZED",
      message: "Authentication failed",
    });
  }
};

/**
 * Middleware to protect routes that require admin API key authentication
 */
const protectWithAdminApiKey = async (req, res, next) => {
  try {
    const apiKey = req.header("X-ADMIN-API-KEY");

    if (!apiKey) {
      return res.status(401).json({
        code: "UNAUTHORIZED",
        message: "No admin API key provided",
      });
    }

    // In a real implementation, you would validate the admin API key against a database
    // For this example, we'll use a simple check against an environment variable
    if (apiKey !== process.env.ADMIN_API_KEY) {
      return res.status(401).json({
        code: "UNAUTHORIZED",
        message: "Invalid admin API key",
      });
    }

    next();
  } catch (error) {
    console.error("Auth error:", error);
    res.status(401).json({
      code: "UNAUTHORIZED",
      message: "Authentication failed",
    });
  }
};

module.exports = {
  protectWithGeneralApiKey,
  protectWithAuthorApiKey,
  protectWithAdminApiKey,
};
