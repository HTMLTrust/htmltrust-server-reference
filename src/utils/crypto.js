const crypto = require("crypto");
const {
  decodeCanonicalBase64,
  normalizeAlgorithm,
  toCanonicalBase64,
} = require("./htmltrustProtocol");

/**
 * Generate a key pair
 * @param {string} algorithm - The algorithm to use (RSA, ECDSA, ED25519)
 * @returns {Object} - Object containing public and private keys
 */
const generateKeyPair = (algorithm = "RSA") => {
  let options;
  const normalized = normalizeAlgorithm(algorithm);

  switch (normalized) {
    case "rsa-pkcs1-sha256":
    case "rsa-pss-sha256":
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
    case "ecdsa-p256":
      options = {
        namedCurve: "prime256v1",
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
    case "ecdsa-p384":
      options = {
        namedCurve: "secp384r1",
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
    case "ed25519":
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
    normalized === "ed25519"
      ? "ed25519"
      : normalized.startsWith("ecdsa")
        ? "ec"
        : "rsa",
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
  const normalized = normalizeAlgorithm(algorithm);

  switch (normalized) {
    case "rsa-pkcs1-sha256":
      sign = crypto.createSign("SHA256");
      sign.update(data);
      return toCanonicalBase64(sign.sign(privateKey));
    case "rsa-pss-sha256":
      sign = crypto.createSign("SHA256");
      sign.update(data);
      return toCanonicalBase64(sign.sign({
        key: privateKey,
        padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
        saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST,
      }));
    case "ecdsa-p256":
      sign = crypto.createSign("SHA256");
      sign.update(data);
      return toCanonicalBase64(sign.sign({ key: privateKey, dsaEncoding: "ieee-p1363" }));
    case "ecdsa-p384":
      sign = crypto.createSign("SHA384");
      sign.update(data);
      return toCanonicalBase64(sign.sign({ key: privateKey, dsaEncoding: "ieee-p1363" }));
    case "ed25519":
      return toCanonicalBase64(crypto.sign(null, Buffer.from(data), privateKey));
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
    const normalized = normalizeAlgorithm(algorithm);
    const decodedSignature = decodeCanonicalBase64(signature, "signature");

    switch (normalized) {
      case "rsa-pkcs1-sha256":
        verify = crypto.createVerify("SHA256");
        verify.update(data);
        return verify.verify(publicKey, decodedSignature);
      case "rsa-pss-sha256":
        verify = crypto.createVerify("SHA256");
        verify.update(data);
        return verify.verify({
          key: publicKey,
          padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
          saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST,
        }, decodedSignature);
      case "ecdsa-p256":
        if (decodedSignature.byteLength !== 64) return false;
        verify = crypto.createVerify("SHA256");
        verify.update(data);
        return verify.verify({ key: publicKey, dsaEncoding: "ieee-p1363" }, decodedSignature);
      case "ecdsa-p384":
        if (decodedSignature.byteLength !== 96) return false;
        verify = crypto.createVerify("SHA384");
        verify.update(data);
        return verify.verify({ key: publicKey, dsaEncoding: "ieee-p1363" }, decodedSignature);
      case "ed25519":
        return crypto.verify(
          null,
          Buffer.from(data),
          publicKey,
          decodedSignature,
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
