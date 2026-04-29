const crypto = require("crypto");

/**
 * Generate a key pair
 * @param {string} algorithm - The algorithm to use (RSA, ECDSA, ED25519)
 * @returns {Object} - Object containing public and private keys
 */
const generateKeyPair = (algorithm = "RSA") => {
  let options;

  switch (algorithm) {
    case "RSA":
      options = {
        modulusLength: 2048,
        publicKeyEncoding: {
          type: "spki",
          format: "pem",
        },
        privateKeyEncoding: {
          type: "pkcs8",
          format: "pem",
        },
      };
      break;
    case "ECDSA":
      options = {
        namedCurve: "secp256k1",
        publicKeyEncoding: {
          type: "spki",
          format: "pem",
        },
        privateKeyEncoding: {
          type: "pkcs8",
          format: "pem",
        },
      };
      break;
    case "ED25519":
      options = {
        publicKeyEncoding: {
          type: "spki",
          format: "pem",
        },
        privateKeyEncoding: {
          type: "pkcs8",
          format: "pem",
        },
      };
      break;
    default:
      throw new Error(`Unsupported algorithm: ${algorithm}`);
  }

  return crypto.generateKeyPairSync(
    algorithm === "ED25519"
      ? "ed25519"
      : algorithm === "ECDSA"
        ? "ec"
        : algorithm.toLowerCase(),
    options,
  );
};

/**
 * Sign content with a private key
 * @param {string} data - The data to sign
 * @param {string} privateKey - The private key in PEM format
 * @param {string} algorithm - The algorithm used for the key
 * @returns {string} - The signature
 */
const signContent = (data, privateKey, algorithm = "RSA") => {
  let sign;

  switch (algorithm) {
    case "RSA":
      sign = crypto.createSign("SHA256");
      sign.update(data);
      return sign.sign(privateKey, "base64");
    case "ECDSA":
      sign = crypto.createSign("SHA256");
      sign.update(data);
      return sign.sign(privateKey, "base64");
    case "ED25519":
      return crypto
        .sign(null, Buffer.from(data), privateKey)
        .toString("base64");
    default:
      throw new Error(`Unsupported algorithm: ${algorithm}`);
  }
};

/**
 * Verify a signature
 * @param {string} data - The data that was signed
 * @param {string} signature - The signature to verify
 * @param {string} publicKey - The public key in PEM format
 * @param {string} algorithm - The algorithm used for the key
 * @returns {boolean} - Whether the signature is valid
 */
const verifySignature = (data, signature, publicKey, algorithm = "RSA") => {
  try {
    let verify;

    switch (algorithm) {
      case "RSA":
        verify = crypto.createVerify("SHA256");
        verify.update(data);
        return verify.verify(publicKey, signature, "base64");
      case "ECDSA":
        verify = crypto.createVerify("SHA256");
        verify.update(data);
        return verify.verify(publicKey, signature, "base64");
      case "ED25519":
        return crypto.verify(
          null,
          Buffer.from(data),
          publicKey,
          Buffer.from(signature, "base64"),
        );
      default:
        throw new Error(`Unsupported algorithm: ${algorithm}`);
    }
  } catch (error) {
    console.error("Verification error:", error);
    return false;
  }
};

/**
 * Lazily loaded normalizeText from @htmltrust/canonicalization (ESM module)
 */
let _normalizeText;
const getNormalizeText = async () => {
  if (!_normalizeText) {
    const mod = await import("@htmltrust/canonicalization");
    _normalizeText = mod.normalizeText;
  }
  return _normalizeText;
};

/**
 * Hash content using SHA-256, applying canonical normalization first.
 *
 * Returns an unpadded Base64-encoded digest prefixed with the algorithm name,
 * per HTMLTrust spec §2.1 "Hash and signature encoding". Example output:
 *
 *   "sha256:RAyBCvKTW5KNnGZSyXZYe+8V8DEEnUMRxjk5LSgCHo4"
 *
 * Callers MUST use the full prefixed form (including "sha256:") when
 * storing or transmitting the hash.
 *
 * @param {string} content - The content to hash
 * @returns {Promise<string>} - The prefixed hash string
 */
const hashContent = async (content) => {
  const normalizeText = await getNormalizeText();
  const normalized = normalizeText(content);
  const digest = crypto
    .createHash("sha256")
    .update(normalized)
    .digest("base64")
    .replace(/=+$/, ""); // unpadded
  return `sha256:${digest}`;
};

/**
 * Hash an already-canonicalized string using SHA-256 with base64 encoding.
 * Use this when the input is already the canonical serialization (e.g., a
 * claims canonical string from canonicalizeClaims()); it skips the text
 * normalization step.
 *
 * @param {string} canonical - Already-canonical string
 * @returns {string} - Prefixed hash (e.g. "sha256:...")
 */
const hashCanonical = (canonical) => {
  const digest = crypto
    .createHash("sha256")
    .update(canonical)
    .digest("base64")
    .replace(/=+$/, "");
  return `sha256:${digest}`;
};

/**
 * Generate a random API key
 * @returns {string} - The API key
 */
const generateApiKey = () => {
  return crypto.randomBytes(32).toString("hex");
};

module.exports = {
  generateKeyPair,
  signContent,
  verifySignature,
  hashContent,
  hashCanonical,
  generateApiKey,
};
