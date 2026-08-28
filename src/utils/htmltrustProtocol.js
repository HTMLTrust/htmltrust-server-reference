const crypto = require("crypto");
const { canonicalizeJcs } = require("./jcs");

/**
 * Build an Error that is safe to echo back to the client.
 *
 * Validation failures describe the caller's own input and are useful in the
 * response body; anything else (driver errors, programming errors, internal
 * state) is an information leak and is replaced by a generic detail. See
 * `detailFor` below.
 */
const invalid = (message) => {
  const error = new Error(message);
  error.expose = true;
  return error;
};

/**
 * Client-safe detail string for an error.
 *
 * Only errors explicitly marked as client-facing (`expose`), Mongoose schema
 * validation errors, and explicit development runs surface the raw message.
 * The default is production behaviour: never leak internal error text.
 */
const detailFor = (error, fallback = "The request could not be processed") => {
  if (!error) return fallback;
  if (error.expose === true) return error.message;
  if (error.name === "ValidationError" || error.name === "CastError") return error.message;
  if (process.env.NODE_ENV === "development") return error.message;
  return fallback;
};

const HASH_LENGTHS = {
  sha256: 32,
  sha384: 48,
  sha512: 64,
};

const SIGNATURE_ALGORITHMS = new Set([
  "ed25519",
  "ecdsa-p256",
  "ecdsa-p384",
  "rsa-pss-sha256",
  "rsa-pkcs1-sha256",
]);

const toCanonicalBase64 = (input) => Buffer.from(input).toString("base64").replace(/=+$/, "");

const decodeCanonicalBase64 = (value, field = "value") => {
  if (typeof value !== "string" || value.length === 0) {
    throw invalid(`${field} must be a non-empty Base64 string`);
  }
  if (!/^[A-Za-z0-9+/]+$/.test(value)) {
    throw invalid(`${field} must use standard unpadded Base64`);
  }

  const padded = value.padEnd(Math.ceil(value.length / 4) * 4, "=");
  const decoded = Buffer.from(padded, "base64");
  if (decoded.length === 0 || toCanonicalBase64(decoded) !== value) {
    throw invalid(`${field} must be canonical unpadded Base64`);
  }
  return decoded;
};

const assertContentHash = (value, field = "contentHash") => {
  if (typeof value !== "string") {
    throw invalid(`${field} must be a string`);
  }
  const [algorithm, digest, ...rest] = value.split(":");
  if (rest.length > 0 || !algorithm || !digest) {
    throw invalid(`${field} must be formatted as <algorithm>:<base64-digest>`);
  }
  const expectedLength = HASH_LENGTHS[algorithm];
  if (!expectedLength) {
    throw invalid(`${field} uses unsupported hash algorithm ${algorithm}`);
  }
  const decoded = decodeCanonicalBase64(digest, field);
  if (decoded.length !== expectedLength) {
    throw invalid(`${field} digest length must be ${expectedLength} bytes`);
  }
  return value;
};

const normalizeAlgorithm = (algorithm = "ed25519") => {
  const normalized = String(algorithm).toLowerCase();
  switch (normalized) {
    case "ed25519":
      return "ed25519";
    case "ecdsa":
    case "ecdsa-p256":
      return "ecdsa-p256";
    case "rsa":
    case "rsa-pkcs1-sha256":
      return "rsa-pkcs1-sha256";
    case "rsa-pss-sha256":
      return "rsa-pss-sha256";
    case "ecdsa-p384":
      return "ecdsa-p384";
    default:
      throw invalid(`Unsupported signature algorithm: ${algorithm}`);
  }
};

const internalAlgorithm = (algorithm = "ed25519") => {
  switch (normalizeAlgorithm(algorithm)) {
    case "ed25519":
      return "ED25519";
    case "ecdsa-p256":
    case "ecdsa-p384":
      return "ECDSA";
    case "rsa-pkcs1-sha256":
    case "rsa-pss-sha256":
      return "RSA";
    default:
      return algorithm;
  }
};

const assertSignatureAlgorithm = (algorithm) => {
  const normalized = normalizeAlgorithm(algorithm);
  if (!SIGNATURE_ALGORITHMS.has(normalized)) {
    throw invalid(`Unsupported signature algorithm: ${algorithm}`);
  }
  return normalized;
};

const normalizeSerializedOrigin = (value, field = "domain") => {
  if (typeof value !== "string" || value.trim() === "") {
    throw invalid(`${field} must be a serialized Web origin`);
  }

  let url;
  try {
    url = new URL(value);
  } catch {
    throw invalid(`${field} must include a scheme and host, for example https://example.com`);
  }

  if (!["http:", "https:"].includes(url.protocol)) {
    throw invalid(`${field} scheme must be http or https`);
  }
  if (url.username || url.password || url.pathname !== "/" || url.search || url.hash) {
    throw invalid(`${field} must not include credentials, path, query, or fragment`);
  }

  const port = url.port ? `:${url.port}` : "";
  return `${url.protocol}//${url.hostname.toLowerCase()}${port}`;
};

const assertRfc3339Utc = (value, field = "timestamp") => {
  if (typeof value !== "string" || Number.isNaN(Date.parse(value))) {
    throw invalid(`${field} must be an RFC3339 date-time`);
  }
  if (!/Z$/.test(value)) {
    throw invalid(`${field} must use UTC (Z)`);
  }
  return value;
};

const keyDocumentFor = (key, kid) => {
  const publicKeyObject = crypto.createPublicKey(key.publicKey);
  const der = publicKeyObject.export({ type: "spki", format: "der" });
  const doc = {
    kid: kid || String(key._id),
    algorithm: normalizeAlgorithm(key.algorithm),
    publicKey: toCanonicalBase64(der),
    publicKeyEncoding: "spki-der",
    revoked: Boolean(key.revoked),
  };
  if (key.expiresAt) {
    doc.expires = key.expiresAt.toISOString();
  }
  if (key.revokedAt) doc.revokedAt = key.revokedAt.toISOString();
  if (key.supersededBy) doc.supersededBy = key.supersededBy;
  if (Array.isArray(key.previousKeys) && key.previousKeys.length > 0) {
    doc.previousKeys = key.previousKeys;
  }
  return doc;
};

const problem = (res, status, title, detail, extra = {}) => {
  // Drop undefined members so a caller passing `{ type: maybeUndefined }`
  // cannot strip the `type` the RFC 9457 document requires.
  const extras = Object.fromEntries(
    Object.entries(extra).filter(([, value]) => value !== undefined),
  );
  res.status(status).type("application/problem+json").json({
    type: extras.type || `https://htmltrust.org/errors/${title.toLowerCase().replace(/[^a-z0-9]+/g, "-")}`,
    title,
    status,
    detail,
    ...extras,
  });
};

/**
 * The endorsement signing payload per draft §10.2: RFC 8785 JCS of the
 * endorsement document with the `signature` member omitted. Every other
 * member — including members this implementation does not recognise — is
 * part of the payload, so the document MUST be canonicalized exactly as it
 * was submitted. Never add, rename, or drop members before calling this.
 */
const canonicalizeEndorsement = (endorsement) => {
  const { signature, ...unsigned } = endorsement;
  return canonicalizeJcs(unsigned);
};

/**
 * Escape every character that carries meaning inside a regular expression, so
 * caller-supplied text can only ever match itself.
 */
const escapeRegExp = (value) => String(value).replace(/[.*+?^${}()|[\]\\\-]/g, "\\$&");

const MAX_SEARCH_TERM = 128;

/**
 * Build a MongoDB `$regex` filter from untrusted search input.
 *
 * Passing user input straight into `$regex` is both an injection vector (the
 * input becomes pattern syntax) and a denial-of-service vector (a crafted
 * pattern backtracks exponentially inside the server). Escaping every
 * metacharacter makes the pattern a literal, the length cap bounds the work
 * per document, and anchoring turns the scan into a prefix match.
 */
const safeSearchRegex = (value, field = "search term") => {
  const term = String(value);
  if (term.length > MAX_SEARCH_TERM) {
    throw invalid(`${field} must be ${MAX_SEARCH_TERM} characters or fewer`);
  }
  return { $regex: `^${escapeRegExp(term)}`, $options: "i" };
};

const normalizeClaims = (claims) => {
  if (claims == null) return [];
  if (Array.isArray(claims)) {
    return claims.map((claim) => ({
      name: String(claim.name),
      content: String(claim.content),
    }));
  }
  return Object.entries(claims).map(([name, content]) => ({
    name,
    content: String(content),
  }));
};

const signedAtFromClaims = (claims) => {
  const claim = normalizeClaims(claims).find((item) => item.name === "signed-at");
  return claim ? claim.content : null;
};

module.exports = {
  assertContentHash,
  assertRfc3339Utc,
  assertSignatureAlgorithm,
  canonicalizeEndorsement,
  decodeCanonicalBase64,
  detailFor,
  escapeRegExp,
  internalAlgorithm,
  invalid,
  keyDocumentFor,
  normalizeAlgorithm,
  normalizeClaims,
  normalizeSerializedOrigin,
  problem,
  safeSearchRegex,
  signedAtFromClaims,
  toCanonicalBase64,
};
