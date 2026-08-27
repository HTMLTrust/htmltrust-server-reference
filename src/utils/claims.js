/**
 * Canonical claims serialization, draft §4.6.
 *
 * The claims hash is part of the signing payload binding (§5), so the
 * directory has to reproduce the signer's byte string exactly:
 *
 *   1. Each claim `name` and `content` is normalized as plain text per §4.4
 *      (NFKC, formatting-character strip, whitespace collapse).
 *   2. Each pair is serialized as `name` `:` `content` `\n`.
 *   3. Lines are sorted by the UTF-8 byte sequence of the *normalized name*
 *      (not by the whole line, and not by UTF-16 code unit).
 *   4. The sorted lines are concatenated.
 *
 * Text normalization and serialization come from the shared
 * `@htmltrust/canonicalization` library so the server cannot drift from the
 * signers. Array input is validated before conversion to an object because an
 * object cannot represent duplicate claim names.
 */

let sharedModulePromise;
const loadShared = () => {
  if (!sharedModulePromise) {
    sharedModulePromise = import("@htmltrust/canonicalization");
  }
  return sharedModulePromise;
};

/**
 * Serialize a claims map to its canonical byte string.
 *
 * @param {Record<string, string>|Array<{name: string, content: string}>} claims
 * @returns {Promise<string>} canonical claims string
 */
const canonicalizeClaims = async (claims) => {
  const shared = await loadShared();
  const entries = Array.isArray(claims)
    ? claims.map((claim) => [claim && claim.name, claim && claim.content])
    : Object.entries(claims || {});

  const seen = new Set();
  const validated = entries.map(([name, content]) => {
    if (name == null || content == null) {
      const error = new Error("claim-malformed: each claim needs a name and content");
      error.expose = true;
      throw error;
    }

    const normalizedName = shared.normalizeText(String(name)).trim();
    if (!normalizedName) {
      const error = new Error("claim-malformed: claim name normalized to the empty string");
      error.expose = true;
      throw error;
    }
    if (seen.has(normalizedName)) {
      const error = new Error(`claim-duplicate: ${normalizedName}`);
      error.expose = true;
      throw error;
    }
    seen.add(normalizedName);
    return [normalizedName, content];
  });

  return shared.canonicalizeClaims(Object.fromEntries(validated));
};

module.exports = { canonicalizeClaims };
