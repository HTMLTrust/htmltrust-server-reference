const crypto = require("crypto");
const { problem } = require("../utils/htmltrustProtocol");
const { resolveUsableKey } = require("../utils/keyResolution");

/**
 * RFC 9421 HTTP Message Signatures, as required by draft §9.8:
 *
 *   "POST endpoints MUST be authenticated using HTTP Message Signatures
 *    [RFC9421] with a key that the directory can resolve via Section 8. The
 *    canonical v1 signature input covers exactly `@method`, `@target-uri`,
 *    `host`, `date`, and `content-digest`, in that order."
 *
 * This is a deliberately small verifier, not a general RFC 9421 library.
 * Strict mode implements the HTMLTrust v1 request profile. Compatibility
 * mode keeps the broader component aliases accepted by the pre-v1 `/api`
 * routes.
 *
 *   Derived components with parameters (`@query-param`, `;req`, `;sf`, `;bs`)
 *   are NOT supported and are rejected rather than silently ignored, because
 *   silently ignoring a covered component would let a signer sign something
 *   other than what is verified.
 *
 * The verified identity is the resolved key, not a shared secret: the
 * `keyid` signature parameter is resolved per draft §8 and the signature is
 * checked against that key. `req.htmltrustActor` is set on success.
 */

// Accepted clock skew for the `created` parameter and the `date` header.
const MAX_SKEW_SECONDS = 300;
const V1_COMPONENTS = ["@method", "@target-uri", "host", "date", "content-digest"];
const IMF_FIXDATE = /^(Mon|Tue|Wed|Thu|Fri|Sat|Sun), \d{2} (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{4} \d{2}:\d{2}:\d{2} GMT$/;

// Signatures already seen inside the acceptance window, to stop a captured
// request from being replayed verbatim. Bounded so it cannot grow without
// limit; a multi-process deployment needs a shared store instead.
const REPLAY_CACHE_LIMIT = 4096;
const seenSignatures = new Map();

const rememberSignature = (signatureB64) => {
  const now = Date.now();
  for (const [value, at] of seenSignatures) {
    if (now - at > MAX_SKEW_SECONDS * 2000) seenSignatures.delete(value);
    else break;
  }
  if (seenSignatures.has(signatureB64)) return false;
  if (seenSignatures.size >= REPLAY_CACHE_LIMIT) {
    const oldest = seenSignatures.keys().next().value;
    seenSignatures.delete(oldest);
  }
  seenSignatures.set(signatureB64, now);
  return true;
};

class SignatureError extends Error {}

/**
 * Split a structured-field dictionary on top-level commas, ignoring commas
 * inside quoted strings, parenthesised inner lists, and byte sequences.
 */
const splitDictionary = (header) => {
  const members = [];
  let depth = 0;
  let inQuotes = false;
  let inBytes = false;
  let start = 0;
  for (let i = 0; i < header.length; i += 1) {
    const ch = header[i];
    if (inQuotes) {
      if (ch === "\\") i += 1;
      else if (ch === '"') inQuotes = false;
      continue;
    }
    if (inBytes) {
      if (ch === ":") inBytes = false;
      continue;
    }
    if (ch === '"') inQuotes = true;
    else if (ch === ":") inBytes = true;
    else if (ch === "(") depth += 1;
    else if (ch === ")") depth -= 1;
    else if (ch === "," && depth === 0) {
      members.push(header.slice(start, i));
      start = i + 1;
    }
  }
  members.push(header.slice(start));
  return members.map((member) => member.trim()).filter(Boolean);
};

const splitLabel = (member) => {
  const eq = member.indexOf("=");
  if (eq === -1) throw new SignatureError("malformed structured field dictionary member");
  return [member.slice(0, eq).trim(), member.slice(eq + 1).trim()];
};

const splitParameters = (tail) => {
  if (tail.length > 0 && !tail.startsWith(";")) {
    throw new SignatureError("signature parameters must follow the inner list");
  }
  const parts = [];
  let inQuotes = false;
  let start = 1;
  for (let index = 1; index < tail.length; index += 1) {
    const ch = tail[index];
    if (inQuotes && ch === "\\") {
      index += 1;
    } else if (ch === '"') {
      inQuotes = !inQuotes;
    } else if (ch === ";" && !inQuotes) {
      parts.push(tail.slice(start, index));
      start = index + 1;
    }
  }
  if (inQuotes) throw new SignatureError("unterminated string signature parameter");
  if (tail.length > 0) parts.push(tail.slice(start));
  return parts;
};

const parseParameterValue = (raw) => {
  if (/^"(?:[\x20-\x21\x23-\x5b\x5d-\x7e]|\\["\\])*"$/.test(raw)) {
    return {
      type: "string",
      value: raw.slice(1, -1).replace(/\\(["\\])/g, "$1"),
    };
  }
  if (/^-?(?:0|[1-9]\d*)$/.test(raw)) {
    const value = Number(raw);
    if (!Number.isSafeInteger(value)) {
      throw new SignatureError("integer signature parameter is outside the safe range");
    }
    return { type: "integer", value };
  }
  if (/^[A-Za-z*][A-Za-z0-9_.*:\/-]*$/.test(raw)) {
    return { type: "token", value: raw };
  }
  if (raw === "?0" || raw === "?1") {
    return { type: "boolean", value: raw === "?1" };
  }
  throw new SignatureError("malformed signature parameter value");
};

/**
 * Parse one `Signature-Input` value: an inner list of quoted component
 * identifiers followed by `;name=value` parameters.
 */
const parseSignatureInputValue = (raw) => {
  if (!raw.startsWith("(")) throw new SignatureError("signature input must start with an inner list");
  const close = raw.indexOf(")");
  if (close === -1) throw new SignatureError("unterminated signature input inner list");

  const inner = raw.slice(1, close).trim();
  const components = [];
  if (inner.length > 0) {
    for (const token of inner.split(/\s+/)) {
      if (!/^"[^"]*"$/.test(token)) {
        throw new SignatureError(`unsupported covered component ${token}`);
      }
      components.push(token.slice(1, -1).toLowerCase());
    }
  }

  const params = {};
  const paramTypes = {};
  const tail = raw.slice(close + 1);
  for (const part of splitParameters(tail)) {
    const chunk = part.trim();
    if (!chunk) continue;
    const eq = chunk.indexOf("=");
    const rawName = (eq === -1 ? chunk : chunk.slice(0, eq)).trim();
    if (!/^[a-z*][a-z0-9_.*-]*$/.test(rawName)) {
      throw new SignatureError(`invalid signature parameter name ${rawName}`);
    }
    const name = rawName.toLowerCase();
    if (Object.hasOwn(params, name)) {
      throw new SignatureError(`duplicate signature parameter ${name}`);
    }
    if (eq === -1) {
      params[name] = true;
      paramTypes[name] = "boolean";
      continue;
    }
    const parsed = parseParameterValue(chunk.slice(eq + 1).trim());
    const { type, value } = parsed;
    params[name] = value;
    paramTypes[name] = type;
  }

  return { components, params, paramTypes, raw };
};

const parseSignatureValue = (raw) => {
  if (!raw.startsWith(":") || !raw.endsWith(":") || raw.length < 2) {
    throw new SignatureError("signature value must be a byte sequence");
  }
  return Buffer.from(raw.slice(1, -1), "base64");
};

const headerValue = (req, name) => {
  const value = req.headers[name];
  if (value === undefined) return undefined;
  return Array.isArray(value) ? value.join(", ") : String(value);
};

/**
 * Build the signature base per RFC 9421 §2.5.
 */
const buildSignatureBase = (req, components, signatureParamsRaw) => {
  const lines = [];
  for (const component of components) {
    let value;
    switch (component) {
      case "@method":
        value = req.method.toUpperCase();
        break;
      case "@target-uri":
        value = `${req.protocol}://${req.get("host")}${req.originalUrl}`;
        break;
      case "@request-target":
        value = req.originalUrl;
        break;
      case "@path":
        value = req.path;
        break;
      case "@query":
        value = req.originalUrl.includes("?") ? req.originalUrl.slice(req.originalUrl.indexOf("?")) : "?";
        break;
      case "@authority":
        value = String(req.get("host") || "").toLowerCase();
        break;
      case "@scheme":
        value = req.protocol;
        break;
      default:
        if (component.startsWith("@")) {
          throw new SignatureError(`unsupported derived component "${component}"`);
        }
        value = headerValue(req, component);
        if (value === undefined) {
          throw new SignatureError(`covered header "${component}" is not present on the request`);
        }
        value = value.replace(/\s+/g, " ").trim();
        break;
    }
    lines.push(`"${component}": ${value}`);
  }
  lines.push(`"@signature-params": ${signatureParamsRaw}`);
  return lines.join("\n");
};

/**
 * Verify Content-Digest (RFC 9530) against the raw request body. Without this
 * the signature covers a digest header that nothing ties to the body.
 */
const verifyContentDigest = (req) => {
  const header = headerValue(req, "content-digest");
  if (!header) throw new SignatureError("content-digest header is required for requests with a body");
  const body = req.rawBody || Buffer.alloc(0);

  let matched = false;
  for (const member of splitDictionary(header)) {
    const [algorithm, raw] = splitLabel(member);
    const name = algorithm.toLowerCase();
    if (name !== "sha-256" && name !== "sha-512") continue;
    const expected = crypto
      .createHash(name === "sha-256" ? "sha256" : "sha512")
      .update(body)
      .digest();
    const provided = parseSignatureValue(raw);
    if (expected.length === provided.length && crypto.timingSafeEqual(expected, provided)) {
      matched = true;
    } else {
      throw new SignatureError("content-digest does not match the request body");
    }
  }
  if (!matched) throw new SignatureError("content-digest must use sha-256 or sha-512");
};

const assertRequiredComponents = (components, hasBody) => {
  const covered = new Set(components);
  const coversTarget =
    covered.has("@method") &&
    (covered.has("@request-target") || covered.has("@target-uri") || covered.has("@path"));
  if (!coversTarget) {
    throw new SignatureError('signature must cover the request target ("@method" and "@target-uri")');
  }
  if (!covered.has("host") && !covered.has("@authority")) {
    throw new SignatureError('signature must cover "host"');
  }
  if (!covered.has("date")) {
    throw new SignatureError('signature must cover "date"');
  }
  if (hasBody && !covered.has("content-digest")) {
    throw new SignatureError('signature must cover "content-digest" when the request has a body');
  }
};

const assertV1Profile = ({ label, components, params, paramTypes, rawSignature }) => {
  if (label !== "sig1") {
    throw new SignatureError('HTMLTrust v1 requires the signature label "sig1"');
  }
  if (
    components.length !== V1_COMPONENTS.length ||
    components.some((component, index) => component !== V1_COMPONENTS[index])
  ) {
    throw new SignatureError(
      `HTMLTrust v1 requires exactly these covered components in order: ${V1_COMPONENTS.join(", ")}`,
    );
  }
  if (paramTypes.created !== "integer" || !Number.isSafeInteger(params.created) || params.created < 0) {
    throw new SignatureError("HTMLTrust v1 requires an integer `created` parameter");
  }
  if (paramTypes.keyid !== "string" || params.keyid.length === 0) {
    throw new SignatureError("HTMLTrust v1 requires a non-empty `keyid` parameter");
  }
  if (paramTypes.alg !== "string" || params.alg !== "ed25519") {
    throw new SignatureError('HTMLTrust v1 requires `alg="ed25519"`');
  }
  if (params.nonce !== undefined && (paramTypes.nonce !== "string" || params.nonce.length === 0)) {
    throw new SignatureError("the `nonce` parameter must be a non-empty string");
  }
  const encoded = rawSignature.slice(1, -1);
  if (!/^[A-Za-z0-9+/]+$/.test(encoded)) {
    throw new SignatureError("HTMLTrust v1 signatures must use canonical unpadded Base64");
  }
  const decoded = Buffer.from(encoded.padEnd(Math.ceil(encoded.length / 4) * 4, "="), "base64");
  const canonical = decoded.toString("base64").replace(/=+$/, "");
  if (canonical !== encoded || decoded.length !== 64) {
    throw new SignatureError(
      "HTMLTrust v1 signatures must be a canonical unpadded Base64 encoding of 64 bytes",
    );
  }
};

const assertFreshness = (req, params) => {
  const now = Math.floor(Date.now() / 1000);
  if (typeof params.created === "number" && Math.abs(now - params.created) > MAX_SKEW_SECONDS) {
    throw new SignatureError("signature `created` timestamp is outside the acceptance window");
  }
  if (typeof params.expires === "number" && params.expires < now) {
    throw new SignatureError("signature has expired");
  }
  const date = headerValue(req, "date");
  const parsed = date ? Date.parse(date) : NaN;
  if (
    !date || !IMF_FIXDATE.test(date) || !Number.isFinite(parsed) ||
    new Date(parsed).toUTCString() !== date
  ) {
    throw new SignatureError("date header must be a valid IMF-fixdate HTTP date");
  }
  if (Math.abs(now - Math.floor(parsed / 1000)) > MAX_SKEW_SECONDS) {
    throw new SignatureError("date header is outside the acceptance window");
  }
};

/**
 * Verify raw signature bytes. RFC 9421 carries ECDSA signatures in the fixed
 * width (r || s) form of IEEE P1363, not the DER encoding Node defaults to,
 * so the encoding is stated explicitly.
 */
const verifyBytes = (base, signature, publicKeyPem, algorithm) => {
  const data = Buffer.from(base, "utf8");
  switch (algorithm) {
    case "ed25519":
      return crypto.verify(null, data, publicKeyPem, signature);
    case "ecdsa-p256":
      return crypto.verify("sha256", data, { key: publicKeyPem, dsaEncoding: "ieee-p1363" }, signature);
    case "ecdsa-p384":
      return crypto.verify("sha384", data, { key: publicKeyPem, dsaEncoding: "ieee-p1363" }, signature);
    case "rsa-pkcs1-sha256":
      return crypto.verify("sha256", data, publicKeyPem, signature);
    case "rsa-pss-sha256":
      return crypto.verify(
        "sha256",
        data,
        {
          key: publicKeyPem,
          padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
          saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST,
        },
        signature,
      );
    default:
      throw new SignatureError(`unsupported signature algorithm ${algorithm}`);
  }
};

/**
 * Verify the request's HTTP Message Signature.
 *
 * `resolve` exists so tests can supply key material directly; production
 * callers use the default, which resolves the keyid per draft section 8.
 *
 * @returns {Promise<{ok: true, actor: object} | {ok: false, status: number, title: string, detail: string}>}
 */
const verifyHttpMessageSignature = async (
  req,
  { resolve = resolveUsableKey, strictV1 = false } = {},
) => {
  const inputHeader = headerValue(req, "signature-input");
  const signatureHeader = headerValue(req, "signature");
  if (!inputHeader || !signatureHeader) {
    return { ok: false, status: 401, title: "Unauthorized", detail: "Signature and Signature-Input headers are required" };
  }

  try {
    const signatureMembers = splitDictionary(signatureHeader).map((member) => splitLabel(member));
    const inputMembers = splitDictionary(inputHeader).map((member) => splitLabel(member));
    if (strictV1) {
      if (
        signatureMembers.length !== 1 ||
        inputMembers.length !== 1 ||
        signatureMembers[0][0] !== "sig1" ||
        inputMembers[0][0] !== "sig1"
      ) {
        throw new SignatureError('HTMLTrust v1 accepts exactly one signature labeled "sig1"');
      }
    }
    const signatures = new Map(signatureMembers);
    // An explicitly captured empty buffer is still a body representation. Its
    // content-digest must bind to the empty byte sequence just like any other
    // raw body; checking `.length > 0` would skip that verification.
    const hasBody = req.rawBody !== undefined && req.rawBody !== null;
    let lastError = null;

    for (const [label, rawValue] of inputMembers) {
      const rawSignature = signatures.get(label);
      if (!rawSignature) continue;

      try {
        const { components, params, paramTypes, raw } = parseSignatureInputValue(rawValue);
        if (strictV1) {
          assertV1Profile({ label, components, params, paramTypes, rawSignature });
        } else {
          if (!params.keyid || typeof params.keyid !== "string") {
            throw new SignatureError("signature is missing a keyid parameter");
          }
          assertRequiredComponents(components, hasBody);
        }
        assertFreshness(req, params);
        // A covered digest always has to be tied back to the exact bytes,
        // including an empty sequence when no parser supplied rawBody.
        if (components.includes("content-digest")) verifyContentDigest(req);

        const resolution = await resolve(params.keyid, { req, algorithm: params.alg });
        if (!resolution.ok) {
          return {
            ok: false,
            status: 401,
            title: "Key resolution failed",
            detail: `The signature keyid could not be resolved to a usable key (${resolution.reason})`,
            type: `https://htmltrust.org/errors/${resolution.reason}`,
          };
        }
        const { resolved } = resolution;
        if (strictV1 && resolved.algorithm !== "ed25519") {
          throw new SignatureError("HTMLTrust v1 request authentication requires an Ed25519 key");
        }
        if (params.alg && params.alg !== resolved.algorithm) {
          throw new SignatureError("signature `alg` does not match the resolved key algorithm");
        }

        const signature = parseSignatureValue(rawSignature);
        const base = buildSignatureBase(req, components, raw);
        if (!verifyBytes(base, signature, resolved.publicKeyPem, resolved.algorithm)) {
          throw new SignatureError("signature did not verify against the resolved key");
        }
        if (!rememberSignature(rawSignature)) {
          throw new SignatureError("signature has already been used (replay)");
        }

        return { ok: true, actor: { keyid: params.keyid, resolved, label } };
      } catch (error) {
        if (!(error instanceof SignatureError)) throw error;
        lastError = error;
      }
    }

    return {
      ok: false,
      status: 401,
      title: "Invalid signature",
      detail: lastError ? lastError.message : "No usable signature was present on the request",
    };
  } catch (error) {
    if (error instanceof SignatureError) {
      return { ok: false, status: 401, title: "Invalid signature", detail: error.message };
    }
    console.error("HTTP message signature verification error:", error);
    return { ok: false, status: 401, title: "Invalid signature", detail: "The request signature could not be verified" };
  }
};

/**
 * Express middleware factory. On success `req.htmltrustActor` holds the
 * verified identity. On failure the response is `401` with a
 * `WWW-Authenticate` challenge, per draft §9.8.
 *
 * `fallback` runs when no HTTP Message Signature is present at all. It exists
 * so the legacy static API-key schemes can stay available for the demo UI and
 * the conformance suite; see `src/middleware/auth.js`.
 */
const requireActorSignature = ({ fallback, strictV1 = false } = {}) => async (req, res, next) => {
  const hasSignature = Boolean(req.headers["signature-input"] || req.headers.signature);
  if (!hasSignature && typeof fallback === "function") {
    return fallback(req, res, next);
  }

  const result = await verifyHttpMessageSignature(req, { strictV1 });
  if (!result.ok) {
    res.set("WWW-Authenticate", 'Signature realm="htmltrust-directory"');
    return problem(res, result.status, result.title, result.detail, result.type ? { type: result.type } : {});
  }
  req.htmltrustActor = result.actor;
  return next();
};

module.exports = {
  buildSignatureBase,
  requireActorSignature,
  V1_COMPONENTS,
  verifyHttpMessageSignature,
};
