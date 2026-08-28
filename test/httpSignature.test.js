const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const { buildSignatureBase, verifyHttpMessageSignature } = require("../src/middleware/httpSignature");

const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519", {
  publicKeyEncoding: { type: "spki", format: "pem" },
  privateKeyEncoding: { type: "pkcs8", format: "pem" },
});

const resolve = async () => ({
  ok: true,
  resolved: { keyid: "test-key", publicKeyPem: publicKey, algorithm: "ed25519" },
});

/** Minimal Express-shaped request. */
const makeRequest = ({ body = "", headers = {}, method = "POST", url = "/api/endorsements" } = {}) => {
  const raw = Buffer.from(body, "utf8");
  const lower = {};
  for (const [name, value] of Object.entries(headers)) lower[name.toLowerCase()] = value;
  return {
    method,
    originalUrl: url,
    path: url.split("?")[0],
    protocol: "http",
    rawBody: raw,
    headers: lower,
    get: (name) => lower[name.toLowerCase()],
  };
};

const digestOf = (body) =>
  `sha-256=:${crypto.createHash("sha256").update(Buffer.from(body, "utf8")).digest("base64")}:`;

/** Sign a request the way a conforming client would. */
const signRequest = ({
  body = '{"a":1}',
  components,
  keyid = "test-key",
  created = Math.floor(Date.now() / 1000),
  date = new Date().toUTCString(),
  alg = "ed25519",
  label = "sig1",
  nonce,
  padded = false,
  bareKeyid = false,
  bareAlg = false,
  bareNonce = false,
} = {}) => {
  const covered = components || ["@method", "@target-uri", "host", "date", "content-digest"];
  const parameters = [
    `created=${created}`,
    `keyid=${bareKeyid ? keyid : `"${keyid}"`}`,
    ...(alg === null ? [] : [`alg=${bareAlg ? alg : `"${alg}"`}`]),
    ...(nonce === undefined ? [] : [`nonce=${bareNonce ? nonce : `"${nonce}"`}`]),
  ];
  const params = `(${covered.map((c) => `"${c}"`).join(" ")});${parameters.join(";")}`;
  const req = makeRequest({
    body,
    headers: {
      host: "directory.example",
      date,
      "content-digest": digestOf(body),
      "signature-input": `${label}=${params}`,
    },
  });
  const base = buildSignatureBase(req, covered, params);
  let signature = crypto.sign(null, Buffer.from(base, "utf8"), privateKey).toString("base64");
  if (!padded) signature = signature.replace(/=+$/, "");
  req.headers.signature = `${label}=:${signature}:`;
  return req;
};

test("builds the RFC 9421 signature base with one line per covered component", () => {
  const req = makeRequest({
    headers: { host: "directory.example", date: "Tue, 20 Apr 2021 02:07:56 GMT" },
    url: "/api/endorsements",
  });
  const params = '("@method" "@target-uri" "host" "date");created=1618884473;keyid="test-key"';
  const base = buildSignatureBase(req, ["@method", "@target-uri", "host", "date"], params);
  assert.equal(
    base,
    [
      '"@method": POST',
      '"@target-uri": http://directory.example/api/endorsements',
      '"host": directory.example',
      '"date": Tue, 20 Apr 2021 02:07:56 GMT',
      `"@signature-params": ${params}`,
    ].join("\n"),
  );
});

test("accepts a correctly signed request", async () => {
  const result = await verifyHttpMessageSignature(signRequest(), { resolve });
  assert.equal(result.ok, true);
  assert.equal(result.actor.keyid, "test-key");
});

test("verifies content-digest for an explicitly captured empty raw body", async () => {
  const req = signRequest({ body: "", nonce: "empty-body" });
  const result = await verifyHttpMessageSignature(req, { resolve });
  assert.equal(result.ok, true);

  const wrongDigest = signRequest({ body: "", nonce: "empty-body-wrong-digest" });
  wrongDigest.headers["content-digest"] = digestOf("different bytes");
  const rejected = await verifyHttpMessageSignature(wrongDigest, { resolve });
  assert.equal(rejected.ok, false);
  assert.match(rejected.detail, /content-digest/);

  const uncaptured = signRequest({ body: "", nonce: "empty-body-not-captured" });
  uncaptured.rawBody = undefined;
  uncaptured.headers["content-digest"] = digestOf("different bytes");
  const uncapturedRejected = await verifyHttpMessageSignature(uncaptured, { resolve });
  assert.equal(uncapturedRejected.ok, false);
  assert.match(uncapturedRejected.detail, /content-digest/);
});

test("strict v1 accepts the exact sig1 request profile", async () => {
  let requestedAlgorithm;
  const result = await verifyHttpMessageSignature(
    signRequest({ body: '{"strict":true}', nonce: "request-1" }),
    {
      resolve: async (keyid, options) => {
        requestedAlgorithm = options.algorithm;
        return resolve(keyid, options);
      },
      strictV1: true,
    },
  );
  assert.equal(result.ok, true);
  assert.equal(requestedAlgorithm, "ed25519");
});

test("strict v1 rejects a missing alg parameter", async () => {
  const result = await verifyHttpMessageSignature(
    signRequest({ body: '{"missing":"alg"}', alg: null }),
    { resolve, strictV1: true },
  );
  assert.equal(result.ok, false);
  assert.match(result.detail, /alg/);
});

test("strict v1 enforces structured-field parameter types", async () => {
  for (const options of [
    { body: '{"bare":"keyid"}', bareKeyid: true },
    { body: '{"bare":"alg"}', bareAlg: true },
    { body: '{"bare":"nonce"}', nonce: "request-2", bareNonce: true },
  ]) {
    const result = await verifyHttpMessageSignature(signRequest(options), {
      resolve,
      strictV1: true,
    });
    assert.equal(result.ok, false);
    assert.match(result.detail, /keyid|alg|nonce/);
  }
});

test("rejects a Date field that is not an IMF-fixdate HTTP date", async () => {
  const result = await verifyHttpMessageSignature(
    signRequest({ body: '{"date":"iso"}', date: new Date().toISOString() }),
    { resolve, strictV1: true },
  );
  assert.equal(result.ok, false);
  assert.match(result.detail, /IMF-fixdate/);
});

test("strict v1 rejects reordered, aliased, or additional components", async () => {
  const cases = [
    ["@target-uri", "@method", "host", "date", "content-digest"],
    ["@method", "@path", "host", "date", "content-digest"],
    ["@method", "@target-uri", "host", "date", "content-digest", "@scheme"],
  ];
  for (let index = 0; index < cases.length; index += 1) {
    const result = await verifyHttpMessageSignature(
      signRequest({ body: `{"case":${index}}`, components: cases[index] }),
      { resolve, strictV1: true },
    );
    assert.equal(result.ok, false);
    assert.match(result.detail, /exactly these covered components/);
  }
});

test("strict v1 rejects labels other than sig1 and padded signatures", async () => {
  const wrongLabel = await verifyHttpMessageSignature(
    signRequest({ body: '{"label":false}', label: "other" }),
    { resolve, strictV1: true },
  );
  assert.equal(wrongLabel.ok, false);
  assert.match(wrongLabel.detail, /sig1/);

  const padded = await verifyHttpMessageSignature(
    signRequest({ body: '{"padding":true}', padded: true }),
    { resolve, strictV1: true },
  );
  assert.equal(padded.ok, false);
  assert.match(padded.detail, /unpadded Base64/);
});

test("strict v1 rejects a noncanonical Base64 spelling with altered pad bits", async () => {
  const req = signRequest({ body: '{"padBits":true}' });
  const match = /^sig1=:([A-Za-z0-9+/]+):$/.exec(req.headers.signature);
  assert.ok(match);
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  const encoded = match[1];
  const lastIndex = alphabet.indexOf(encoded.at(-1));
  assert.equal(lastIndex % 16, 0);
  const alternate = encoded.slice(0, -1) + alphabet[lastIndex + 1];
  assert.deepEqual(
    Buffer.from(alternate, "base64"),
    Buffer.from(encoded, "base64"),
  );
  req.headers.signature = `sig1=:${alternate}:`;

  const result = await verifyHttpMessageSignature(req, { resolve, strictV1: true });
  assert.equal(result.ok, false);
  assert.match(result.detail, /canonical unpadded Base64/);
});

test("rejects a request whose body was swapped after signing", async () => {
  const req = signRequest({ body: '{"a":1}' });
  // Same headers, different body: the content-digest no longer matches.
  req.rawBody = Buffer.from('{"a":2}', "utf8");
  const result = await verifyHttpMessageSignature(req, { resolve });
  assert.equal(result.ok, false);
  assert.match(result.detail, /content-digest/);
});

test("rejects a request whose target was changed after signing", async () => {
  const req = signRequest();
  req.originalUrl = "/api/content";
  req.path = "/api/content";
  const result = await verifyHttpMessageSignature(req, { resolve });
  assert.equal(result.ok, false);
});

test("rejects a signature that does not cover content-digest on a body request", async () => {
  const req = signRequest({ components: ["@method", "@target-uri", "host", "date"] });
  const result = await verifyHttpMessageSignature(req, { resolve });
  assert.equal(result.ok, false);
  assert.match(result.detail, /content-digest/);
});

test("rejects a signature that does not cover the request target", async () => {
  const req = signRequest({ components: ["host", "date", "content-digest"] });
  const result = await verifyHttpMessageSignature(req, { resolve });
  assert.equal(result.ok, false);
  assert.match(result.detail, /request target/);
});

test("rejects @request-target without @method", async () => {
  const req = signRequest({ components: ["@request-target", "host", "date", "content-digest"] });
  const result = await verifyHttpMessageSignature(req, { resolve });
  assert.equal(result.ok, false);
  assert.match(result.detail, /request target/);
});

test("rejects a stale signature", async () => {
  const req = signRequest({
    created: Math.floor(Date.now() / 1000) - 3600,
    date: new Date(Date.now() - 3600_000).toUTCString(),
  });
  const result = await verifyHttpMessageSignature(req, { resolve });
  assert.equal(result.ok, false);
  assert.match(result.detail, /acceptance window/);
});

test("rejects a replayed signature", async () => {
  const req = signRequest({ body: '{"replay":true}' });
  assert.equal((await verifyHttpMessageSignature(req, { resolve })).ok, true);
  const second = await verifyHttpMessageSignature(req, { resolve });
  assert.equal(second.ok, false);
  assert.match(second.detail, /replay/);
});

test("rejects a request with no signature at all", async () => {
  const req = makeRequest({ headers: { host: "directory.example", date: new Date().toUTCString() } });
  const result = await verifyHttpMessageSignature(req, { resolve });
  assert.equal(result.ok, false);
  assert.equal(result.status, 401);
});

test("rejects a signature whose keyid does not resolve", async () => {
  const req = signRequest();
  const result = await verifyHttpMessageSignature(req, {
    resolve: async () => ({ ok: false, reason: "key-resolution-failed" }),
  });
  assert.equal(result.ok, false);
  assert.equal(result.status, 401);
  assert.match(result.detail, /key-resolution-failed/);
});

test("rejects an alg parameter that disagrees with the resolved key", async () => {
  const body = '{"a":1}';
  const covered = ["@method", "@target-uri", "host", "date", "content-digest"];
  const params = `(${covered.map((c) => `"${c}"`).join(" ")});created=${Math.floor(Date.now() / 1000)};keyid="test-key";alg="rsa-pss-sha256"`;
  const req = makeRequest({
    body,
    headers: {
      host: "directory.example",
      date: new Date().toUTCString(),
      "content-digest": digestOf(body),
      "signature-input": `sig1=${params}`,
    },
  });
  const base = buildSignatureBase(req, covered, params);
  req.headers.signature = `sig1=:${crypto.sign(null, Buffer.from(base, "utf8"), privateKey).toString("base64")}:`;

  const result = await verifyHttpMessageSignature(req, { resolve });
  assert.equal(result.ok, false);
  assert.match(result.detail, /alg/);
});
