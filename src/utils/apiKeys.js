const crypto = require("crypto");

/**
 * API key storage and comparison.
 *
 * Author API keys are bearer credentials. Storing them verbatim means a read
 * of the `authors` collection (backup, dump, injection, misconfigured replica)
 * hands over every author's ability to sign content. They are therefore
 * stored as an HMAC-SHA-256 of the key under a server-held pepper, and looked
 * up by that value.
 *
 * A per-record random salt is deliberately not used: the lookup is
 * "find the author for this presented key", which a per-record salt would
 * turn into a full collection scan with one HMAC per author. The pepper lives
 * outside the database, so a database-only compromise still cannot verify or
 * reverse a key, and the keys themselves are 256 bits of `crypto.randomBytes`
 * output, so there is no dictionary to precompute against.
 *
 * MIGRATION: rows created before this change carry a plaintext `apiKey` and
 * no `apiKeyHash`. There is no way to derive the hash without the plaintext,
 * so the one-time migration is:
 *
 *   db.authors.find({ apiKey: { $exists: true } }).forEach(a =>
 *     db.authors.updateOne(
 *       { _id: a._id },
 *       { $set: { apiKeyHash: hmacSha256(pepper, a.apiKey) },
 *         $unset: { apiKey: "" } }));
 *
 * Run it with the same AUTHOR_API_KEY_PEPPER the server will use. Existing
 * keys keep working; changing the pepper afterwards invalidates every key and
 * requires reissuing them.
 */

const DEV_PEPPER = "htmltrust-development-pepper-do-not-use-in-production";

let cachedPepper;

const pepper = () => {
  if (cachedPepper !== undefined) return cachedPepper;
  const configured = process.env.AUTHOR_API_KEY_PEPPER;
  if (configured && configured.length > 0) {
    cachedPepper = configured;
    return cachedPepper;
  }
  if (process.env.NODE_ENV === "production") {
    throw new Error(
      "AUTHOR_API_KEY_PEPPER must be set in production; author API keys cannot be stored safely without it",
    );
  }
  console.warn(
    "AUTHOR_API_KEY_PEPPER is not set — falling back to a well-known development pepper. Set it before deploying.",
  );
  cachedPepper = DEV_PEPPER;
  return cachedPepper;
};

/** Deterministic, indexable hash of an API key. */
const hashApiKey = (apiKey) =>
  crypto.createHmac("sha256", pepper()).update(String(apiKey)).digest("hex");

/**
 * Constant-time comparison of two secrets of unequal length.
 *
 * `crypto.timingSafeEqual` throws on a length mismatch, which would itself
 * leak the length, so both sides are hashed to a fixed width first.
 */
const secretsMatch = (provided, expected) => {
  if (typeof provided !== "string" || typeof expected !== "string" || expected.length === 0) {
    return false;
  }
  const a = crypto.createHash("sha256").update(provided).digest();
  const b = crypto.createHash("sha256").update(expected).digest();
  return crypto.timingSafeEqual(a, b);
};

/**
 * Resolve the pepper once at startup so a production deployment missing it
 * fails immediately instead of at the first request that needs it.
 */
const assertConfigured = () => {
  pepper();
};

module.exports = { assertConfigured, hashApiKey, secretsMatch };
