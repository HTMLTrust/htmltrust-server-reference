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
 * Text normalization comes from the shared `@htmltrust/canonicalization`
 * library so the server cannot drift from the signers. That library also
 * exports `canonicalizeClaims`; the version currently pinned in package.json
 * (v0.1.0) exports only `normalizeText`, so `canonicalizeClaims` is used when
 * present and reproduced on top of `normalizeText` otherwise. Once the pin is
 * bumped past v0.1.0 the fallback below can be deleted.
 */

let sharedModulePromise;
const loadShared = () => {
  if (!sharedModulePromise) {
    sharedModulePromise = import("@htmltrust/canonicalization");
  }
  return sharedModulePromise;
};

/**
 * Compare by Unicode code point, which is the same ordering as comparing the
 * UTF-8 encodings. JavaScript's default string comparison is UTF-16 code-unit
 * order, which mis-sorts supplementary-plane characters relative to high-BMP
 * ones and would produce a different claims hash than a UTF-8 signer.
 */
const compareByCodePoint = (a, b) => {
  const ai = Array.from(a);
  const bi = Array.from(b);
  const n = Math.min(ai.length, bi.length);
  for (let i = 0; i < n; i += 1) {
    const ca = ai[i].codePointAt(0);
    const cb = bi[i].codePointAt(0);
    if (ca !== cb) return ca - cb;
  }
  return ai.length - bi.length;
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

  if (typeof shared.canonicalizeClaims === "function") {
    return shared.canonicalizeClaims(Object.fromEntries(entries));
  }

  const { normalizeText } = shared;
  const seen = new Set();
  const lines = entries
    .map(([name, content]) => {
      if (name == null || content == null) {
        const error = new Error("claim-malformed: each claim needs a name and content");
        error.expose = true;
        throw error;
      }
      return [normalizeText(String(name)).trim(), normalizeText(String(content)).trim()];
    })
    .map(([name, content]) => {
      if (!name) {
        const error = new Error("claim-malformed: claim name normalized to the empty string");
        error.expose = true;
        throw error;
      }
      if (seen.has(name)) {
        const error = new Error(`claim-duplicate: ${name}`);
        error.expose = true;
        throw error;
      }
      seen.add(name);
      return [name, content];
    })
    .sort(([a], [b]) => compareByCodePoint(a, b));

  return lines.map(([name, content]) => `${name}:${content}\n`).join("");
};

module.exports = { canonicalizeClaims };
