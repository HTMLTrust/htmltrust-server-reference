const Author = require("../models/Author");
const { problem } = require("../utils/htmltrustProtocol");
const { hashApiKey, secretsMatch } = require("../utils/apiKeys");

/**
 * Static API-key authentication.
 *
 * Draft §9.8 requires POST endpoints to be authenticated with an RFC 9421
 * HTTP Message Signature bound to a resolvable key (see
 * `middleware/httpSignature.js`). The shared-secret schemes below are a
 * supplementary admin/demo scheme only: a shared `X-API-KEY` proves nothing
 * about *who* submitted a record, so it cannot carry the identity that
 * content and endorsement ingestion depend on.
 *
 * `apiKeyAuthEnabled()` gates them off in production. Set
 * HTMLTRUST_ALLOW_API_KEY_AUTH=1 to re-enable them there (for an operator
 * console, for example) with full knowledge that they are not an identity.
 */
const apiKeyAuthEnabled = () => {
  if (process.env.HTMLTRUST_ALLOW_API_KEY_AUTH === "1") return true;
  if (process.env.HTMLTRUST_ALLOW_API_KEY_AUTH === "0") return false;
  return process.env.NODE_ENV !== "production";
};

const unauthorized = (res, detail, scheme = "ApiKey") => {
  // Draft §9.8: an unauthenticated request MUST get a WWW-Authenticate
  // challenge. Routes that accept an RFC 9421 signature advertise it first so
  // a client learns the scheme it is supposed to be using.
  const schemes = Array.isArray(scheme) ? scheme : [scheme];
  res.set(
    "WWW-Authenticate",
    schemes.map((name) => `${name} realm="htmltrust-directory"`).join(", "),
  );
  return problem(res, 401, "Unauthorized", detail, {
    type: "https://htmltrust.org/errors/unauthorized",
  });
};

/**
 * Middleware to protect routes that require general API key authentication
 */
const protectWithGeneralApiKey = async (req, res, next) => {
  try {
    if (!apiKeyAuthEnabled()) {
      return unauthorized(
        res,
        "Static API-key authentication is disabled; submit an RFC 9421 HTTP Message Signature instead",
        "Signature",
      );
    }

    const apiKey = req.header("X-API-KEY");
    if (!apiKey) {
      return unauthorized(
        res,
        "Provide an RFC 9421 HTTP Message Signature, or the demo API key in X-API-KEY",
        ["Signature", "ApiKey"],
      );
    }
    if (!secretsMatch(apiKey, process.env.GENERAL_API_KEY || "")) {
      return unauthorized(res, "Invalid API key", ["Signature", "ApiKey"]);
    }

    return next();
  } catch (error) {
    console.error("Auth error:", error);
    return unauthorized(res, "Authentication failed");
  }
};

/**
 * Middleware to protect routes that require author-specific API key authentication
 */
const protectWithAuthorApiKey = async (req, res, next) => {
  try {
    if (!apiKeyAuthEnabled()) {
      return unauthorized(
        res,
        "Static API-key authentication is disabled; submit an RFC 9421 HTTP Message Signature instead",
        "Signature",
      );
    }

    const apiKey = req.header("X-AUTHOR-API-KEY");
    if (!apiKey) {
      return unauthorized(res, "No author API key provided");
    }

    // Look the author up by the hash of the presented key; the plaintext key
    // is never stored, so there is nothing to compare against directly.
    const author = await Author.findOne({ apiKeyHash: hashApiKey(apiKey) });
    if (!author) {
      return unauthorized(res, "Invalid author API key");
    }

    if (req.params.authorId && req.params.authorId !== author._id.toString()) {
      return problem(res, 403, "Forbidden", "API key does not match author", {
        type: "https://htmltrust.org/errors/forbidden",
      });
    }

    req.author = author;
    return next();
  } catch (error) {
    console.error("Auth error:", error);
    return unauthorized(res, "Authentication failed");
  }
};

/**
 * Middleware to protect routes that require admin API key authentication
 */
const protectWithAdminApiKey = async (req, res, next) => {
  try {
    const apiKey = req.header("X-ADMIN-API-KEY");
    if (!apiKey) {
      return unauthorized(res, "No admin API key provided");
    }
    if (!secretsMatch(apiKey, process.env.ADMIN_API_KEY || "")) {
      return unauthorized(res, "Invalid admin API key");
    }

    req.isDirectoryAdmin = true;
    return next();
  } catch (error) {
    console.error("Auth error:", error);
    return unauthorized(res, "Authentication failed");
  }
};

/** True when the request carries a valid directory-admin key. */
const hasAdminApiKey = (req) => {
  const apiKey = req.header("X-ADMIN-API-KEY");
  return Boolean(apiKey) && secretsMatch(apiKey, process.env.ADMIN_API_KEY || "");
};

module.exports = {
  apiKeyAuthEnabled,
  hasAdminApiKey,
  protectWithGeneralApiKey,
  protectWithAuthorApiKey,
  protectWithAdminApiKey,
  unauthorized,
};
