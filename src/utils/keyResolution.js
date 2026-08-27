const crypto = require("crypto");
const dns = require("dns").promises;
const net = require("net");
const Key = require("../models/Key");
const { normalizeAlgorithm } = require("./htmltrustProtocol");

/**
 * Key resolution, draft §8.
 *
 * A keyid is opaque to the protocol; §8 defines three resolution methods:
 * DID (§8.1), a direct HTTPS URL to a key document (§8.2), and a trust
 * directory `/keys/{id}` reference (§8.3). This module resolves a keyid to a
 * PEM public key so that ingestion paths can verify signatures rather than
 * trusting the submitter.
 *
 * Remote resolution (DID and HTTPS) is DISABLED by default. A directory that
 * dereferences attacker-supplied URLs on an unauthenticated ingest path is a
 * server-side request forgery primitive: the submitter chooses the host, the
 * port, and the timing of an outbound request made from inside the
 * directory's network. Operators who need it opt in with
 * HTMLTRUST_REMOTE_KEY_RESOLUTION=1, and even then resolution is restricted
 * to https, refuses redirects, refuses non-public IP addresses, bounds the
 * response size, and times out. With remote resolution off, keyids that do
 * not name a key held by this directory are simply unresolvable, and the
 * submission is rejected.
 */

const REMOTE_ENABLED = () => process.env.HTMLTRUST_REMOTE_KEY_RESOLUTION === "1";
const REMOTE_TIMEOUT_MS = 5000;
const REMOTE_MAX_BYTES = 64 * 1024;
const OBJECT_ID = /^[0-9a-fA-F]{24}$/;

/**
 * Pull a directory key id out of a keyid string. Accepts a bare ObjectId or
 * any URL whose path contains a `/keys/{id}` segment (draft §8.3).
 */
const directoryKeyIdFrom = (keyid) => {
  if (typeof keyid !== "string" || keyid.length === 0) return null;
  if (OBJECT_ID.test(keyid)) return keyid;
  let url;
  try {
    url = new URL(keyid);
  } catch {
    return null;
  }
  const segments = url.pathname.split("/").filter(Boolean);
  const keysIndex = segments.lastIndexOf("keys");
  if (keysIndex === -1 || !segments[keysIndex + 1]) return null;
  const candidate = decodeURIComponent(segments[keysIndex + 1]);
  return OBJECT_ID.test(candidate) ? candidate : null;
};

/**
 * True when `keyid` names this directory rather than some other host. Without
 * this check a `/keys/{id}` URL pointing at a different directory would be
 * satisfied from our own database whenever the object ids happened to
 * collide.
 */
const isSelfHosted = (keyid, selfOrigins) => {
  if (typeof keyid !== "string") return false;
  if (OBJECT_ID.test(keyid)) return true;
  try {
    const url = new URL(keyid);
    return selfOrigins.includes(`${url.protocol}//${url.host}`.toLowerCase());
  } catch {
    return false;
  }
};

const selfOriginsFor = (req) => {
  const origins = [];
  if (req && typeof req.get === "function") {
    const host = req.get("host");
    if (host) {
      origins.push(`http://${host}`.toLowerCase());
      origins.push(`https://${host}`.toLowerCase());
    }
  }
  if (process.env.DIRECTORY_BASE_URL) {
    try {
      const url = new URL(process.env.DIRECTORY_BASE_URL);
      origins.push(`${url.protocol}//${url.host}`.toLowerCase());
    } catch {
      /* ignore a malformed configuration value */
    }
  }
  return origins;
};

const isExpired = (expires) => {
  if (!expires) return false;
  const at = expires instanceof Date ? expires.getTime() : Date.parse(expires);
  return Number.isFinite(at) && at <= Date.now();
};

const resolveLocal = async (keyid, selfOrigins) => {
  if (!isSelfHosted(keyid, selfOrigins)) return null;
  const id = directoryKeyIdFrom(keyid);
  if (!id) return null;
  const key = await Key.findById(id);
  if (!key) return null;
  return {
    keyid,
    publicKeyPem: key.publicKey,
    algorithm: normalizeAlgorithm(key.algorithm),
    revoked: Boolean(key.revoked),
    expires: key.expiresAt || null,
    source: "directory",
    key,
  };
};

/**
 * Reject hosts that resolve to loopback, link-local, or RFC 1918 space before
 * making an outbound request. This is checked before the fetch, so a hostile
 * DNS server can still race it (TOCTOU); it raises the cost of SSRF rather
 * than eliminating it, which is why remote resolution stays opt-in.
 */
const assertPublicHost = async (hostname) => {
  const literal = net.isIP(hostname) ? [{ address: hostname }] : await dns.lookup(hostname, { all: true });
  for (const { address } of literal) {
    if (
      /^127\./.test(address) ||
      /^10\./.test(address) ||
      /^192\.168\./.test(address) ||
      /^169\.254\./.test(address) ||
      /^172\.(1[6-9]|2[0-9]|3[01])\./.test(address) ||
      address === "0.0.0.0" ||
      address === "::1" ||
      /^f[cd][0-9a-f]{2}:/i.test(address) ||
      /^fe80:/i.test(address)
    ) {
      throw new Error(`refusing to resolve a key from non-public address ${address}`);
    }
  }
};

const fetchJson = async (url) => {
  const target = new URL(url);
  if (target.protocol !== "https:") {
    throw new Error("key documents may only be fetched over https");
  }
  await assertPublicHost(target.hostname);

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), REMOTE_TIMEOUT_MS);
  try {
    const response = await fetch(target, {
      redirect: "error",
      signal: controller.signal,
      headers: { accept: "application/htmltrust-key+json, application/jwk+json, application/json" },
    });
    if (!response.ok) throw new Error(`key document fetch returned ${response.status}`);
    const declaredLength = Number(response.headers.get("content-length"));
    if (Number.isFinite(declaredLength) && declaredLength > REMOTE_MAX_BYTES) {
      throw new Error("key document exceeds the size limit");
    }
    if (!response.body) throw new Error("key document response has no body");
    const chunks = [];
    let received = 0;
    for await (const chunk of response.body) {
      received += chunk.byteLength;
      if (received > REMOTE_MAX_BYTES) {
        controller.abort();
        throw new Error("key document exceeds the size limit");
      }
      chunks.push(Buffer.from(chunk));
    }
    return JSON.parse(Buffer.concat(chunks, received).toString("utf8"));
  } finally {
    clearTimeout(timer);
  }
};

const pemFromKeyDocument = (document) => {
  if (document && document.kty) {
    // RFC 7517 JSON Web Key (draft §8.2 permits either shape).
    return crypto
      .createPublicKey({ key: document, format: "jwk" })
      .export({ type: "spki", format: "pem" });
  }
  if (document && typeof document.publicKey === "string") {
    if (document.publicKey.includes("BEGIN PUBLIC KEY")) return document.publicKey;
    const der = Buffer.from(document.publicKey, "base64");
    return crypto
      .createPublicKey({ key: der, format: "der", type: "spki" })
      .export({ type: "spki", format: "pem" });
  }
  throw new Error("key document does not contain a usable public key");
};

const algorithmFromKeyDocument = (document) => {
  if (document && document.algorithm) return normalizeAlgorithm(document.algorithm);
  if (document && document.alg) {
    switch (document.alg) {
      case "EdDSA":
        return "ed25519";
      case "ES256":
        return "ecdsa-p256";
      case "ES384":
        return "ecdsa-p384";
      case "RS256":
        return "rsa-pkcs1-sha256";
      case "PS256":
        return "rsa-pss-sha256";
      default:
        break;
    }
  }
  if (document && document.kty === "OKP" && document.crv === "Ed25519") return "ed25519";
  throw new Error("key document does not declare a supported algorithm");
};

/** did:web resolution per §8.1, restricted to the did:web method. */
const didWebUrl = (did) => {
  const rest = did.slice("did:web:".length);
  if (!rest) throw new Error("malformed did:web identifier");
  const parts = rest.split(":").map(decodeURIComponent);
  const host = parts.shift();
  const path = parts.length > 0 ? `/${parts.join("/")}/did.json` : "/.well-known/did.json";
  return `https://${host}${path}`;
};

const resolveDidWeb = async (did) => {
  const document = await fetchJson(didWebUrl(did));
  const methods = Array.isArray(document.verificationMethod) ? document.verificationMethod : [];
  const assertion = Array.isArray(document.assertionMethod) ? document.assertionMethod : [];
  const preferred =
    methods.find((method) => assertion.includes(method.id)) || methods[0];
  if (!preferred) throw new Error("DID document has no verification method");
  const material = preferred.publicKeyJwk || preferred;
  return {
    publicKeyPem: pemFromKeyDocument(material),
    algorithm: algorithmFromKeyDocument(material),
    revoked: false,
    expires: null,
    source: "did:web",
  };
};

/**
 * Resolve a keyid to a public key.
 *
 * @param {string} keyid
 * @param {{ req?: import('express').Request }} options
 * @returns {Promise<{keyid: string, publicKeyPem: string, algorithm: string,
 *   revoked: boolean, expires: Date|string|null, source: string, key?: object}|null>}
 *   null when the keyid cannot be resolved.
 */
const resolveKeyId = async (keyid, { req } = {}) => {
  if (typeof keyid !== "string" || keyid.length === 0 || keyid.length > 2048) return null;

  const local = await resolveLocal(keyid, selfOriginsFor(req));
  if (local) return local;

  if (!REMOTE_ENABLED()) return null;

  try {
    if (keyid.startsWith("did:web:")) {
      return { keyid, ...(await resolveDidWeb(keyid)) };
    }
    if (keyid.startsWith("did:")) {
      // Other DID methods need a method-specific resolver; §8.1 allows an
      // implementation to support a subset, and an unsupported method is a
      // resolution failure rather than a silent pass.
      return null;
    }
    if (keyid.startsWith("https://")) {
      const document = await fetchJson(keyid);
      return {
        keyid,
        publicKeyPem: pemFromKeyDocument(document),
        algorithm: algorithmFromKeyDocument(document),
        revoked: document.revoked === true,
        expires: document.expires || null,
        source: "https",
      };
    }
  } catch (error) {
    console.error(`Key resolution failed for ${keyid}:`, error.message);
    return null;
  }

  return null;
};

/**
 * Resolve and reject keys that draft §8.2 says MUST NOT be used: revoked keys
 * and keys whose `expires` is in the past.
 *
 * @returns {Promise<{ok: true, resolved: object} | {ok: false, reason: string}>}
 */
const resolveUsableKey = async (keyid, options) => {
  const resolved = await resolveKeyId(keyid, options);
  if (!resolved) return { ok: false, reason: "key-resolution-failed" };
  if (resolved.revoked) return { ok: false, reason: "key-revoked" };
  if (isExpired(resolved.expires)) return { ok: false, reason: "key-expired" };
  return { ok: true, resolved };
};

/**
 * Compare two resolved keys by their SPKI bytes. Two keyids can name the same
 * key through different resolution methods, so authorization decisions
 * compare key material rather than keyid strings.
 */
const sameKeyMaterial = (a, b) => {
  if (!a || !b) return false;
  try {
    const der = (pem) => crypto.createPublicKey(pem).export({ type: "spki", format: "der" });
    return der(a).equals(der(b));
  } catch {
    return false;
  }
};

module.exports = {
  directoryKeyIdFrom,
  resolveKeyId,
  resolveUsableKey,
  sameKeyMaterial,
};
