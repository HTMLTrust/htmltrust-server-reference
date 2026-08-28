const crypto = require("crypto");
const dns = require("dns").promises;
const https = require("https");
const net = require("net");
const Key = require("../models/Key");
const {
  assertRfc3339Utc,
  decodeCanonicalBase64,
  normalizeAlgorithm,
} = require("./htmltrustProtocol");

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
const OPAQUE_KEY_ID = /^k_[A-Za-z0-9_-]{20,64}$/;

/**
 * Pull a directory key id out of a keyid string. Accepts a bare legacy
 * ObjectId or an opaque public id in a URL whose path contains a
 * `/keys/{id}` segment (draft §8.3).
 */
const directoryKeyIdFrom = (keyid) => {
  if (typeof keyid !== "string" || keyid.length === 0) return null;
  if (OBJECT_ID.test(keyid) || OPAQUE_KEY_ID.test(keyid)) return keyid;
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
  return OBJECT_ID.test(candidate) || OPAQUE_KEY_ID.test(candidate) ? candidate : null;
};

/**
 * True when `keyid` names this directory rather than some other host. Without
 * this check a `/keys/{id}` URL pointing at a different directory would be
 * satisfied from our own database whenever the object ids happened to
 * collide.
 */
const isSelfHosted = (keyid, selfOrigins) => {
  if (typeof keyid !== "string") return false;
  if (OBJECT_ID.test(keyid) || OPAQUE_KEY_ID.test(keyid)) return true;
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
  return !Number.isFinite(at) || at <= Date.now();
};

/**
 * DID verification methods can carry the same lifecycle fields as an
 * HTMLTrust key document. A malformed lifecycle value is unusable as well,
 * since accepting it would turn an untrusted DID document into a key grant.
 */
const isUsableDidMethod = (method) => {
  if (!method || typeof method !== "object" || Array.isArray(method)) return false;
  if (method.revoked === true) return false;
  if (method.revoked !== undefined && typeof method.revoked !== "boolean") return false;

  for (const field of ["expires", "expiresAt"]) {
    if (method[field] !== undefined) {
      const expiresAt = method[field] instanceof Date
        ? method[field].getTime()
        : typeof method[field] === "string" && method[field].length > 0
          ? Date.parse(method[field])
          : NaN;
      if (!Number.isFinite(expiresAt) || expiresAt <= Date.now()) return false;
    }
  }
  if (method.revokedAt !== undefined) {
    const revokedAt = method.revokedAt instanceof Date
      ? method.revokedAt.getTime()
      : typeof method.revokedAt === "string" && method.revokedAt.length > 0
        ? Date.parse(method.revokedAt)
        : NaN;
    if (!Number.isFinite(revokedAt) || revokedAt <= Date.now()) return false;
  }
  return true;
};

/**
 * Restrict DID verification method types to key material this resolver can
 * actually verify. DID Core requires `type`; omitting it leaves the verifier
 * without the algorithm binding required by the HTMLTrust profile.
 */
const isCompatibleDidMethodType = (method, algorithm) => {
  if (method.type === undefined) return false;
  const types = Array.isArray(method.type) ? method.type : [method.type];
  if (types.length === 0 || types.some((type) => typeof type !== "string")) return false;

  const keyForm = method.publicKeyJwk || method.kty ? "jwk" :
    method.publicKeyMultibase ? "multibase" :
      method.publicKeyBase58 ? "base58" : "unknown";
  if (keyForm !== "jwk") return false;

  const compatible = types.map((type) => type.includes("#") ? type.slice(type.lastIndexOf("#") + 1) : type);
  if (compatible.some((type) => ![
    "JsonWebKey2020",
    "Ed25519VerificationKey2018",
    "Ed25519VerificationKey2020",
    "EcdsaSecp256r1VerificationKey2019",
    "EcdsaSecp256r1VerificationKey2020",
    "EcdsaSecp384r1VerificationKey2019",
    "EcdsaSecp384r1VerificationKey2020",
    "RsaVerificationKey2018",
    "RsaVerificationKey2020",
  ].includes(type))) return false;

  return compatible.some((type) => {
    switch (type) {
      case "JsonWebKey2020":
        return true;
      case "Ed25519VerificationKey2018":
      case "Ed25519VerificationKey2020":
        return algorithm === "ed25519";
      case "EcdsaSecp256r1VerificationKey2019":
      case "EcdsaSecp256r1VerificationKey2020":
        return algorithm === "ecdsa-p256";
      case "EcdsaSecp384r1VerificationKey2019":
      case "EcdsaSecp384r1VerificationKey2020":
        return algorithm === "ecdsa-p384";
      case "RsaVerificationKey2018":
      case "RsaVerificationKey2020":
        return algorithm === "rsa-pkcs1-sha256" || algorithm === "rsa-pss-sha256";
      default:
        return false;
    }
  });
};

const resolveLocal = async (keyid, selfOrigins, requestedAlgorithm) => {
  if (!isSelfHosted(keyid, selfOrigins)) return null;
  const id = directoryKeyIdFrom(keyid);
  if (!id) return null;
  const key = OBJECT_ID.test(id)
    ? await Key.findById(id)
    : await Key.findOne({ publicId: id });
  if (!key) return null;
  const algorithm = normalizeAlgorithm(key.algorithm);
  if (requestedAlgorithm && algorithm !== requestedAlgorithm) return null;
  return {
    keyid,
    publicKeyPem: key.publicKey,
    algorithm,
    revoked: Boolean(key.revoked),
    expires: key.expiresAt || null,
    source: "directory",
    key,
  };
};

/**
 * Return true only for globally routable addresses. This deliberately errs on
 * the side of refusing special-use space, including documentation, benchmark,
 * multicast, and transition ranges. The address returned here is also pinned
 * to the eventual TLS connection by fetchJson's `lookup` callback.
 */
const ipv4ToNumber = (address) => {
  const parts = address.split(".").map(Number);
  if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) return null;
  return (((parts[0] * 256 + parts[1]) * 256 + parts[2]) * 256) + parts[3];
};

const inIpv4Range = (address, network, prefix) => {
  const value = ipv4ToNumber(address);
  const base = ipv4ToNumber(network);
  if (value === null || base === null) return false;
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  return ((value >>> 0) & mask) === ((base >>> 0) & mask);
};

const parseIpv6 = (address) => {
  let value = address.toLowerCase().replace(/^\[|\]$/g, "");
  if (value.includes("%")) return null;
  if (value.includes(".")) {
    const split = value.lastIndexOf(":");
    const ipv4 = ipv4ToNumber(value.slice(split + 1));
    if (split < 0 || ipv4 === null) return null;
    value = `${value.slice(0, split)}:${(ipv4 >>> 16).toString(16)}:${(ipv4 & 0xffff).toString(16)}`;
  }
  const halves = value.split("::");
  if (halves.length > 2) return null;
  const left = halves[0] ? halves[0].split(":") : [];
  const right = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
  if (left.concat(right).some((part) => !/^[0-9a-f]{1,4}$/.test(part))) return null;
  const missing = 8 - left.length - right.length;
  if ((halves.length === 1 && missing !== 0) || (halves.length === 2 && missing < 1)) return null;
  const segments = left.concat(Array(missing).fill("0"), right);
  return segments.reduce((result, segment) => (result << 16n) | BigInt(parseInt(segment, 16)), 0n);
};

const inIpv6Range = (value, network, prefix) => {
  const base = parseIpv6(network);
  if (value === null || base === null) return false;
  return (value >> BigInt(128 - prefix)) === (base >> BigInt(128 - prefix));
};

const isPublicAddress = (address) => {
  const family = net.isIP(address);
  if (family === 4) {
    // RFC 6890 special-use and other non-global IPv4 ranges.
    return ![
      ["0.0.0.0", 8], ["10.0.0.0", 8], ["100.64.0.0", 10], ["127.0.0.0", 8],
      ["169.254.0.0", 16], ["172.16.0.0", 12], ["192.0.0.0", 24], ["192.0.2.0", 24],
      ["192.88.99.0", 24], ["192.168.0.0", 16], ["198.18.0.0", 15], ["198.51.100.0", 24],
      ["203.0.113.0", 24], ["224.0.0.0", 4], ["240.0.0.0", 4],
    ].some(([network, prefix]) => inIpv4Range(address, network, prefix));
  }
  if (family !== 6) return false;
  const value = parseIpv6(address);
  if (value === null) return false;
  // IPv4-mapped addresses inherit the routability of their embedded IPv4.
  if (inIpv6Range(value, "::ffff:0:0", 96)) {
    const embedded = Number(value & 0xffffffffn);
    const ipv4 = `${embedded >>> 24}.${(embedded >>> 16) & 255}.${(embedded >>> 8) & 255}.${embedded & 255}`;
    return isPublicAddress(ipv4);
  }
  // Global unicast is 2000::/3. Everything outside it is special-use,
  // including loopback, ULA, link-local, multicast, and unspecified space.
  if (!inIpv6Range(value, "2000::", 3)) return false;
  return ![
    ["2001:db8::", 32], ["2001:10::", 28], ["2001:20::", 28],
    ["2001:2::", 48], ["2001::", 32], ["2002::", 16],
  ].some(([network, prefix]) => inIpv6Range(value, network, prefix));
};

const resolvePublicAddresses = async (hostname) => {
  const host = hostname.replace(/^\[|\]$/g, "");
  const addresses = net.isIP(host)
    ? [{ address: host, family: net.isIP(host) }]
    : await dns.lookup(host, { all: true });
  if (!addresses.length) throw new Error("key document host did not resolve");
  for (const { address } of addresses) {
    if (!isPublicAddress(address)) {
      throw new Error(`refusing to resolve a key from non-public address ${address}`);
    }
  }
  return addresses;
};

const fetchJson = async (url, acceptedMediaTypes) => {
  const target = new URL(url);
  if (target.protocol !== "https:") {
    throw new Error("key documents may only be fetched over https");
  }
  if (target.username || target.password) throw new Error("key document URLs may not contain credentials");
  if (target.port && target.port !== "443") throw new Error("key documents may only use HTTPS port 443");
  const addresses = await resolvePublicAddresses(target.hostname);
  return new Promise((resolve, reject) => {
    let settled = false;
    let request;
    const timer = setTimeout(() => request.destroy(new Error("key document fetch timed out")), REMOTE_TIMEOUT_MS);
    const fail = (error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      reject(error);
    };
    const succeed = (value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(value);
    };
    request = https.request({
      protocol: target.protocol,
      hostname: target.hostname.replace(/^\[|\]$/g, ""),
      port: target.port || 443,
      path: `${target.pathname}${target.search}`,
      servername: net.isIP(target.hostname.replace(/^\[|\]$/g, "")) ? undefined : target.hostname,
      method: "GET",
      headers: { accept: "application/htmltrust-key+json, application/jwk+json, application/json" },
      // The validated address is used for this request, closing the DNS
      // validation/request TOCTOU window and DNS rebinding race.
      lookup: (_hostname, options, callback) => {
        const selected = addresses[0];
        const family = selected.family || net.isIP(selected.address);
        if (options?.all) {
          callback(null, [{ address: selected.address, family }]);
        } else {
          callback(null, selected.address, family);
        }
      },
    }, (response) => {
      response.on("error", fail);
      const status = response.statusCode || 0;
      if (status < 200 || status >= 300) {
        response.resume();
        fail(new Error(`key document fetch returned ${status}`));
        return;
      }
      const headers = response.headers || {};
      const mediaType = String(headers["content-type"] || "")
        .split(";", 1)[0].trim().toLowerCase();
      if (!acceptedMediaTypes.includes(mediaType)) {
        response.resume();
        fail(new Error(`key document has unsupported media type ${mediaType || "(missing)"}`));
        return;
      }
      let headerBytes = 0;
      for (const [name, value] of Object.entries(headers)) {
        headerBytes += Buffer.byteLength(name) + Buffer.byteLength(Array.isArray(value) ? value.join(",") : String(value)) + 4;
      }
      const declaredLength = Number(headers["content-length"]);
      if (headerBytes > REMOTE_MAX_BYTES || (Number.isFinite(declaredLength) && declaredLength + headerBytes > REMOTE_MAX_BYTES)) {
        response.resume();
        fail(new Error("key document exceeds the size limit"));
        return;
      }
      const chunks = [];
      let received = headerBytes;
      response.on("data", (chunk) => {
        received += chunk.length;
        if (received > REMOTE_MAX_BYTES) {
          fail(new Error("key document exceeds the size limit"));
          request.destroy();
          return;
        }
        chunks.push(Buffer.from(chunk));
      });
      response.on("end", () => {
        if (received > REMOTE_MAX_BYTES) return;
        try {
          succeed({ document: JSON.parse(Buffer.concat(chunks).toString("utf8")), mediaType });
        } catch (error) {
          fail(error);
        }
      });
    });
    request.setTimeout(REMOTE_TIMEOUT_MS, () => {
      fail(new Error("key document fetch timed out"));
      request.destroy();
    });
    request.on("error", fail);
    request.end();
  });
};

const algorithmFromJwk = (document, { allowTypeInference = false, requestedAlgorithm } = {}) => {
  if (document && typeof document.alg === "string") {
    switch (document.alg) {
      case "EdDSA": return "ed25519";
      case "ES256": return "ecdsa-p256";
      case "ES384": return "ecdsa-p384";
      case "RS256": return "rsa-pkcs1-sha256";
      case "PS256": return "rsa-pss-sha256";
      default: throw new Error(`JWK declares unsupported alg ${document.alg}`);
    }
  }
  if (allowTypeInference) {
    if (document?.kty === "OKP" && document.crv === "Ed25519") return "ed25519";
    if (document?.kty === "EC" && document.crv === "P-256") return "ecdsa-p256";
    if (document?.kty === "EC" && document.crv === "P-384") return "ecdsa-p384";
    // RSA JWKs do not encode the padding/hash choice. A declared requested
    // algorithm supplies that missing part when the DID method omits `alg`.
    if (document?.kty === "RSA" && requestedAlgorithm?.startsWith("rsa-")) return requestedAlgorithm;
  }
  throw new Error("JWK must declare a supported alg");
};

const assertKeyMatchesAlgorithm = (keyObject, algorithm) => {
  const type = keyObject.asymmetricKeyType;
  const details = keyObject.asymmetricKeyDetails || {};
  const matches = {
    ed25519: type === "ed25519",
    "ecdsa-p256": type === "ec" && details.namedCurve === "prime256v1",
    "ecdsa-p384": type === "ec" && details.namedCurve === "secp384r1",
    "rsa-pkcs1-sha256": type === "rsa",
    "rsa-pss-sha256": type === "rsa" || type === "rsa-pss",
  }[algorithm];
  if (!matches) throw new Error(`public key parameters do not match ${algorithm}`);
};

const validateOptionalKeyFields = (document) => {
  if (document.expires !== undefined) {
    if (typeof document.expires !== "string") throw new Error("expires must be a string");
    assertRfc3339Utc(document.expires, "expires");
  }
  if (document.revoked !== undefined && typeof document.revoked !== "boolean") {
    throw new Error("revoked must be a boolean");
  }
  if (document.revokedAt !== undefined) {
    if (typeof document.revokedAt !== "string") throw new Error("revokedAt must be a string");
    assertRfc3339Utc(document.revokedAt, "revokedAt");
  }
  if (document.supersededBy !== undefined && typeof document.supersededBy !== "string") {
    throw new Error("supersededBy must be a string");
  }
  if (
    document.previousKeys !== undefined &&
    (!Array.isArray(document.previousKeys) || document.previousKeys.some((value) => typeof value !== "string"))
  ) {
    throw new Error("previousKeys must be an array of strings");
  }
};

const resolveHtmlTrustKeyDocument = (document, requestedKeyid, requestedAlgorithm) => {
  if (!document || typeof document !== "object" || Array.isArray(document)) {
    throw new Error("key document must be a JSON object");
  }
  if (document.kid !== undefined) {
    if (typeof document.kid !== "string" || document.kid !== requestedKeyid) {
      throw new Error("key document kid does not match the requested keyid");
    }
  }
  if (document.publicKeyEncoding !== "spki-der") {
    throw new Error('publicKeyEncoding must be exactly "spki-der"');
  }
  if (typeof document.algorithm !== "string") {
    throw new Error("key document algorithm is required");
  }
  const algorithm = normalizeAlgorithm(document.algorithm);
  if (algorithm !== document.algorithm) {
    throw new Error(`key document algorithm must use the canonical identifier ${algorithm}`);
  }
  if (requestedAlgorithm && algorithm !== requestedAlgorithm) {
    throw new Error(`key document algorithm does not match the requested algorithm ${requestedAlgorithm}`);
  }
  const der = decodeCanonicalBase64(document.publicKey, "publicKey");
  const keyObject = crypto.createPublicKey({ key: der, format: "der", type: "spki" });
  assertKeyMatchesAlgorithm(keyObject, algorithm);
  validateOptionalKeyFields(document);
  return {
    publicKeyPem: keyObject.export({ type: "spki", format: "pem" }),
    algorithm,
  };
};

const resolveJwk = (document, options = {}) => {
  if (!document || typeof document !== "object" || Array.isArray(document) || !document.kty) {
    throw new Error("JWK must be a JSON object with kty");
  }
  const algorithm = algorithmFromJwk(document, options);
  if (options.requestedAlgorithm && algorithm !== options.requestedAlgorithm) {
    throw new Error(`JWK algorithm does not match the requested algorithm ${options.requestedAlgorithm}`);
  }
  const keyObject = crypto.createPublicKey({ key: document, format: "jwk" });
  assertKeyMatchesAlgorithm(keyObject, algorithm);
  return {
    publicKeyPem: keyObject.export({ type: "spki", format: "pem" }),
    algorithm,
  };
};

/** did:web resolution per §8.1, restricted to the did:web method. */
const didWebUrl = (did) => {
  const documentDid = did.split("#", 1)[0];
  const rest = documentDid.slice("did:web:".length);
  if (!rest) throw new Error("malformed did:web identifier");
  const parts = rest.split(":").map(decodeURIComponent);
  const host = parts.shift();
  const path = parts.length > 0 ? `/${parts.join("/")}/did.json` : "/.well-known/did.json";
  return `https://${host}${path}`;
};

const resolveDidWeb = async (did, requestedAlgorithm) => {
  const { document } = await fetchJson(didWebUrl(did), [
    "application/did+json",
    "application/did+ld+json",
    "application/ld+json",
    "application/json",
  ]);
  const methods = Array.isArray(document.verificationMethod)
    ? document.verificationMethod.filter((method) => method && typeof method === "object" && !Array.isArray(method))
    : [];
  const methodsById = new Map();
  const duplicateMethodIds = new Set();
  for (const method of methods) {
    if (typeof method.id !== "string") continue;
    if (methodsById.has(method.id)) duplicateMethodIds.add(method.id);
    else methodsById.set(method.id, method);
  }
  const assertion = Array.isArray(document.assertionMethod) ? document.assertionMethod : [];
  const authorized = [];
  const seenAuthorizationIds = new Set();
  for (const entry of assertion) {
    const embedded = entry && typeof entry === "object" && !Array.isArray(entry) ? entry : null;
    const id = typeof entry === "string" ? entry : embedded?.id;
    if (typeof id !== "string" || seenAuthorizationIds.has(id)) continue;
    seenAuthorizationIds.add(id);
    if (duplicateMethodIds.has(id)) continue;
    // An embedded relationship entry is itself a verification method. If it
    // only carries an id, use the full method from verificationMethod. A
    // linked method is authoritative, preventing an embedded duplicate from
    // replacing its key material under the same id.
    authorized.push(methodsById.get(id) || embedded);
  }
  const fragment = did.includes("#");
  const ordered = authorized.filter((method) => method && (!fragment || method.id === did));
  if (!ordered.length) throw new Error(fragment ? "DID verification method was not found" : "DID document has no verification method");
  let lastError;
  const seen = new Set();
  for (const preferred of ordered) {
    if (!preferred) continue;
    const identity = preferred.id || preferred;
    if (seen.has(identity)) continue;
    seen.add(identity);
    if (!isUsableDidMethod(preferred)) {
      lastError = new Error("DID verification method is revoked or expired");
      if (fragment) break;
      continue;
    }
    try {
      const material = preferred.publicKeyJwk || preferred;
      const resolved = resolveJwk(material, { allowTypeInference: true, requestedAlgorithm });
      if (!isCompatibleDidMethodType(preferred, resolved.algorithm)) {
        throw new Error("DID verification method type does not match its key algorithm");
      }
      return {
        ...resolved,
        revoked: false,
        expires: preferred.expires || preferred.expiresAt || null,
        source: "did:web",
      };
    } catch (error) {
      lastError = error;
      // A fragment names one exact method. Do not silently substitute another
      // key if that method is malformed or uses a different algorithm.
      if (fragment) break;
    }
  }
  throw lastError || new Error("DID document has no compatible verification method");
};

/**
 * Resolve a keyid to a public key.
 *
 * @param {string} keyid
 * @param {{ req?: import('express').Request, algorithm?: string }} options
 * @returns {Promise<{keyid: string, publicKeyPem: string, algorithm: string,
 *   revoked: boolean, expires: Date|string|null, source: string, key?: object}|null>}
 *   null when the keyid cannot be resolved.
 */
const resolveKeyId = async (keyid, { req, algorithm } = {}) => {
  if (typeof keyid !== "string" || keyid.length === 0 || keyid.length > 2048) return null;

  let requestedAlgorithm;
  try {
    requestedAlgorithm = algorithm === undefined ? undefined : normalizeAlgorithm(algorithm);
  } catch {
    return null;
  }

  const local = await resolveLocal(keyid, selfOriginsFor(req), requestedAlgorithm);
  if (local) return local;

  if (!REMOTE_ENABLED()) return null;

  try {
    if (keyid.startsWith("did:web:")) {
      return { keyid, ...(await resolveDidWeb(keyid, requestedAlgorithm)) };
    }
    if (keyid.startsWith("did:")) {
      // Other DID methods need a method-specific resolver; §8.1 allows an
      // implementation to support a subset, and an unsupported method is a
      // resolution failure rather than a silent pass.
      return null;
    }
    if (keyid.startsWith("https://")) {
      const { document, mediaType } = await fetchJson(keyid, [
        "application/htmltrust-key+json",
        "application/jwk+json",
        "application/json",
      ]);
      const keyMaterial = mediaType === "application/jwk+json" || document?.kty
        ? resolveJwk(document, { requestedAlgorithm })
        : resolveHtmlTrustKeyDocument(document, keyid, requestedAlgorithm);
      return {
        keyid,
        ...keyMaterial,
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
