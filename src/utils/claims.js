/**
 * HTMLTrust v1 claim normalization and serialization.
 *
 * Claims are normalized as plain text, checked before serialization, sorted
 * by the UTF-8 bytes of their normalized names, and escaped so the record
 * grammar stays injective.
 */

const MAX_CLAIMS = 64;
const MAX_CLAIM_BYTES = 4 * 1024;

let sharedModulePromise;
const loadShared = () => {
  if (!sharedModulePromise) {
    sharedModulePromise = import("@htmltrust/canonicalization");
  }
  return sharedModulePromise;
};

const claimError = (code, detail) => {
  const error = new Error(`${code}: ${detail}`);
  error.expose = true;
  return error;
};

const escapeClaimField = (value) => value.replace(/[\\:\n]/g, (character) => {
  if (character === "\\") return "\\\\";
  if (character === ":") return "\\:";
  return "\\n";
});

const asEntries = (claims, strictArray) => {
  if (strictArray && !Array.isArray(claims)) {
    throw claimError("claim-malformed", "claims must be an array");
  }
  if (Array.isArray(claims)) {
    return claims.map((claim) => {
      if (!claim || typeof claim !== "object" || Array.isArray(claim)) {
        throw claimError("claim-malformed", "each claim must be an object");
      }
      if (strictArray) {
        const keys = Object.keys(claim).sort();
        if (keys.length !== 2 || keys[0] !== "content" || keys[1] !== "name") {
          throw claimError("claim-malformed", "each claim must contain only name and content");
        }
        if (typeof claim.name !== "string" || typeof claim.content !== "string") {
          throw claimError("claim-malformed", "claim name and content must be strings");
        }
      }
      return [claim.name, claim.content];
    });
  }
  if (!claims || typeof claims !== "object") {
    throw claimError("claim-malformed", "claims must be an object or array");
  }
  return Object.entries(claims);
};

/**
 * Normalize and validate a complete set of direct-child claim records.
 *
 * @param {unknown} claims
 * @param {{strictArray?: boolean}} options
 * @returns {Promise<Array<{name: string, content: string}>>}
 */
const normalizeClaims = async (claims, { strictArray = false } = {}) => {
  const entries = asEntries(claims, strictArray);
  if (entries.length > MAX_CLAIMS) {
    throw claimError("resource-limit-exceeded", `a section may contain at most ${MAX_CLAIMS} claims`);
  }

  const shared = await loadShared();
  const seen = new Set();
  const normalized = entries.map(([name, content]) => {
    if (name == null || content == null) {
      throw claimError("claim-malformed", "each claim needs a name and content");
    }
    const normalizedName = shared.normalizeText(String(name)).trim();
    const normalizedContent = shared.normalizeText(String(content)).trim();
    if (!normalizedName) {
      throw claimError("claim-malformed", "claim name normalized to the empty string");
    }
    if (
      Buffer.byteLength(normalizedName, "utf8") > MAX_CLAIM_BYTES ||
      Buffer.byteLength(normalizedContent, "utf8") > MAX_CLAIM_BYTES
    ) {
      throw claimError(
        "resource-limit-exceeded",
        `normalized claim names and values may be at most ${MAX_CLAIM_BYTES} bytes`,
      );
    }
    if (seen.has(normalizedName)) {
      throw claimError("claim-duplicate", normalizedName);
    }
    seen.add(normalizedName);
    return { name: normalizedName, content: normalizedContent };
  });

  normalized.sort((left, right) => Buffer.compare(
    Buffer.from(left.name, "utf8"),
    Buffer.from(right.name, "utf8"),
  ));
  return normalized;
};

/** Serialize claims to the v1 canonical byte string. */
const canonicalizeClaims = async (claims, options) => {
  const normalized = await normalizeClaims(claims, options);
  return normalized
    .map(({ name, content }) => `${escapeClaimField(name)}:${escapeClaimField(content)}\n`)
    .join("");
};

module.exports = {
  canonicalizeClaims,
  escapeClaimField,
  MAX_CLAIMS,
  MAX_CLAIM_BYTES,
  normalizeClaims,
};
