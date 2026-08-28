const crypto = require("crypto");
const { canonicalizeJcs } = require("./jcs");
const {
  assertContentHash,
  decodeCanonicalBase64,
  invalid,
  normalizeAlgorithm,
} = require("./htmltrustProtocol");
const { canonicalizeClaims, normalizeClaims } = require("./claims");

const PROFILE = Object.freeze({
  signature: "htmltrust-signature-v1",
  canonicalization: "htmltrust-c14n-v1",
  attributes: "htmltrust-attrs-v1",
  url: "htmltrust-safe-url-v1",
  context: "https://htmltrust.org/protocol/signed-section",
});

const HASH_NAMES = Object.freeze({
  sha256: "sha256",
  sha384: "sha384",
  sha512: "sha512",
});

const EXACT_TIMESTAMP = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})Z$/;
const ASCII_CONTROL = /[\u0000-\u001f\u007f]/;
const ASCII_EDGE_WHITESPACE = /^[\u0009-\u000d\u0020]|[\u0009-\u000d\u0020]$/;

const assertProtocolString = (value, field) => {
  if (typeof value !== "string" || value.length === 0) {
    throw invalid(`${field} must be a non-empty string`);
  }
  if (ASCII_EDGE_WHITESPACE.test(value) || ASCII_CONTROL.test(value)) {
    throw invalid(`${field} contains forbidden ASCII whitespace or control characters`);
  }
  return value;
};

const daysInMonth = (year, month) => {
  if (month === 2) {
    const leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
    return leap ? 29 : 28;
  }
  return [4, 6, 9, 11].includes(month) ? 30 : 31;
};

const assertV1Timestamp = (value, field = "signedAt") => {
  if (typeof value !== "string") {
    throw invalid(`${field} must use YYYY-MM-DDTHH:MM:SSZ`);
  }
  const match = EXACT_TIMESTAMP.exec(value);
  if (!match) {
    throw invalid(`${field} must use YYYY-MM-DDTHH:MM:SSZ`);
  }
  const [, yearRaw, monthRaw, dayRaw, hourRaw, minuteRaw, secondRaw] = match;
  const year = Number(yearRaw);
  const month = Number(monthRaw);
  const day = Number(dayRaw);
  const hour = Number(hourRaw);
  const minute = Number(minuteRaw);
  const second = Number(secondRaw);
  if (
    year < 1 || month < 1 || month > 12 || day < 1 ||
    day > daysInMonth(year, month) || hour > 23 || minute > 59 || second > 59
  ) {
    throw invalid(`${field} is not a valid Gregorian UTC date and time`);
  }
  return value;
};

const deriveLocation = (sourceURL, scope) => {
  assertProtocolString(sourceURL, "sourceURL");
  if (scope !== "url" && scope !== "origin") {
    throw invalid("scope must be exactly url or origin");
  }
  let parsed;
  try {
    parsed = new URL(sourceURL);
  } catch {
    throw invalid("sourceURL must be an absolute URL");
  }
  if (parsed.protocol !== "https:" || parsed.username || parsed.password) {
    throw invalid("sourceURL must use HTTPS and must not contain credentials");
  }
  if (scope === "origin") return parsed.origin;
  parsed.hash = "";
  return parsed.href;
};

const hashCanonicalClaims = (canonicalClaims, algorithm) => {
  const hashName = HASH_NAMES[algorithm];
  if (!hashName) throw invalid(`unsupported content hash algorithm ${algorithm}`);
  const digest = crypto
    .createHash(hashName)
    .update(canonicalClaims, "utf8")
    .digest("base64")
    .replace(/=+$/, "");
  return `${algorithm}:${digest}`;
};

const signingObjectFor = ({
  algorithm,
  claimsHash,
  contentHash,
  keyid,
  location,
  scope,
  signedAt,
}) => ({
  algorithm,
  attributeProfile: PROFILE.attributes,
  canonicalizationProfile: PROFILE.canonicalization,
  claimsHash,
  contentHash,
  context: PROFILE.context,
  keyid,
  location,
  profile: PROFILE.signature,
  scope,
  signedAt,
  urlProfile: PROFILE.url,
});

const assertCanonicalAlgorithm = (algorithm) => {
  assertProtocolString(algorithm, "algorithm");
  const normalized = normalizeAlgorithm(algorithm);
  if (normalized !== algorithm) {
    throw invalid(`algorithm must use the canonical identifier ${normalized}`);
  }
  return algorithm;
};

const assertSignatureShape = (signature, algorithm) => {
  const decoded = decodeCanonicalBase64(signature, "signature");
  const exactLengths = {
    ed25519: 64,
    "ecdsa-p256": 64,
    "ecdsa-p384": 96,
  };
  if (exactLengths[algorithm] && decoded.length !== exactLengths[algorithm]) {
    throw invalid(`signature must decode to ${exactLengths[algorithm]} bytes for ${algorithm}`);
  }
  return signature;
};

/**
 * Validate the unsigned fields of a v1 content submission and construct the
 * exact payload that the signature covers.  Directory convenience signers use
 * this before creating the signature; POST /content uses the same helper and
 * then verifies the caller-supplied signature.
 */
const buildV1ContentSigningPayload = async (body) => {
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    throw invalid("the content submission must be a JSON object");
  }
  if (Object.hasOwn(body, "claimsHash")) {
    throw invalid("claimsHash is computed by the directory and must not be submitted");
  }
  if (body.profile !== PROFILE.signature) {
    throw invalid(`profile must be exactly ${PROFILE.signature}`);
  }

  const contentHash = assertContentHash(body.contentHash, "contentHash");
  const hashAlgorithm = contentHash.slice(0, contentHash.indexOf(":"));
  const algorithm = assertCanonicalAlgorithm(body.algorithm);
  const keyid = assertProtocolString(body.keyid, "keyid");
  if (Buffer.byteLength(keyid, "utf8") > 2048) {
    throw invalid("keyid must be 2048 bytes or fewer");
  }
  const signedAt = assertV1Timestamp(body.signedAt, "signedAt");
  const scope = body.scope;
  const location = deriveLocation(body.sourceURL, scope);
  if (body.location !== location) {
    throw invalid(`location must equal the ${scope} location derived from sourceURL`);
  }
  const normalizedClaims = await normalizeClaims(body.claims, { strictArray: true });
  const signedAtClaims = normalizedClaims.filter((claim) => claim.name === "signed-at");
  if (signedAtClaims.length !== 1) {
    throw invalid("claims must contain exactly one signed-at record");
  }
  assertV1Timestamp(signedAtClaims[0].content, "signed-at claim");
  if (signedAtClaims[0].content !== signedAt) {
    throw invalid("the normalized signed-at claim must equal signedAt");
  }

  const canonicalClaims = await canonicalizeClaims(body.claims, { strictArray: true });
  const claimsHash = hashCanonicalClaims(canonicalClaims, hashAlgorithm);
  const signingObject = signingObjectFor({
    algorithm,
    claimsHash,
    contentHash,
    keyid,
    location,
    scope,
    signedAt,
  });
  return {
    algorithm,
    canonicalClaims,
    claims: normalizedClaims,
    claimsHash,
    contentHash,
    keyid,
    location,
    payload: canonicalizeJcs(signingObject),
    profile: PROFILE.signature,
    scope,
    signedAt,
    sourceURL: body.sourceURL,
  };
};

/**
 * Validate a POST /content body and construct the exact v1 signing payload.
 */
const validateV1ContentSubmission = async (body) => {
  const prepared = await buildV1ContentSigningPayload(body);
  return {
    ...prepared,
    signature: assertSignatureShape(body.signature, prepared.algorithm),
  };
};

module.exports = {
  assertV1Timestamp,
  buildV1ContentSigningPayload,
  deriveLocation,
  hashCanonicalClaims,
  PROFILE,
  signingObjectFor,
  validateV1ContentSubmission,
};
