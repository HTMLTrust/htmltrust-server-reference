const test = require("node:test");
const assert = require("node:assert/strict");
const https = require("node:https");
const dns = require("node:dns").promises;
const { EventEmitter } = require("node:events");
const { Readable } = require("node:stream");
const { resolveKeyId } = require("../src/utils/keyResolution");

const mockHttps = ({ body, status = 200, headers = {}, onRequest } = {}) => {
  const previous = https.request;
  let destroyed = false;
  https.request = (options, callback) => {
    onRequest?.(options);
    const request = new EventEmitter();
    request.setTimeout = () => {};
    request.destroy = (error) => {
      destroyed = true;
      if (error) process.nextTick(() => request.emit("error", error));
    };
    request.end = () => process.nextTick(() => {
      const response = new Readable({ read() {} });
      response.statusCode = typeof status === "function" ? status() : status;
      response.headers = typeof headers === "function" ? headers() : headers;
      callback(response);
      if (!destroyed) {
        const value = typeof body === "function" ? body() : body;
        response.push(Buffer.isBuffer(value) ? value : Buffer.from(String(value ?? "")));
        response.push(null);
      }
    });
    return request;
  };
  return { restore: () => { https.request = previous; }, wasDestroyed: () => destroyed };
};

test("remote key resolution stops reading after the 64 KiB limit", async () => {
  const previousEnabled = process.env.HTMLTRUST_REMOTE_KEY_RESOLUTION;
  const previousConsoleError = console.error;
  const requestMock = mockHttps({
    body: Buffer.alloc(64 * 1024 + 1),
    headers: { "content-type": "application/htmltrust-key+json" },
  });
  console.error = () => {};
  process.env.HTMLTRUST_REMOTE_KEY_RESOLUTION = "1";

  try {
    const resolved = await resolveKeyId("https://93.184.216.34/key.json");
    assert.equal(resolved, null);
    assert.equal(requestMock.wasDestroyed(), true);
  } finally {
    requestMock.restore();
    console.error = previousConsoleError;
    if (previousEnabled === undefined) delete process.env.HTMLTRUST_REMOTE_KEY_RESOLUTION;
    else process.env.HTMLTRUST_REMOTE_KEY_RESOLUTION = previousEnabled;
  }
});

test("remote key resolution rejects IPv4-mapped loopback literals", async () => {
  const previousEnabled = process.env.HTMLTRUST_REMOTE_KEY_RESOLUTION;
  let fetched = false;
  const requestMock = mockHttps({
    body: "{}",
    headers: { "content-type": "application/json" },
    onRequest: () => {
      fetched = true;
    },
  });
  process.env.HTMLTRUST_REMOTE_KEY_RESOLUTION = "1";
  try {
    assert.equal(await resolveKeyId("https://[::ffff:127.0.0.1]/key.json"), null);
    assert.equal(fetched, false);
  } finally {
    requestMock.restore();
    if (previousEnabled === undefined) delete process.env.HTMLTRUST_REMOTE_KEY_RESOLUTION;
    else process.env.HTMLTRUST_REMOTE_KEY_RESOLUTION = previousEnabled;
  }
});

test("remote key resolution rejects special-use IPv4 and IPv6 ranges", async () => {
  const previousEnabled = process.env.HTMLTRUST_REMOTE_KEY_RESOLUTION;
  const previousConsoleError = console.error;
  const requestMock = mockHttps({
    body: "{}",
    headers: { "content-type": "application/json" },
    onRequest: () => assert.fail("a special-use address must not be requested"),
  });
  console.error = () => {};
  process.env.HTMLTRUST_REMOTE_KEY_RESOLUTION = "1";
  try {
    for (const keyid of [
      "https://100.64.0.1/key.json",
      "https://198.18.0.1/key.json",
      "https://[fc00::1]/key.json",
      "https://[fe80::1]/key.json",
      "https://[2001:db8::1]/key.json",
      "https://[ff02::1]/key.json",
    ]) {
      assert.equal(await resolveKeyId(keyid), null, keyid);
    }
  } finally {
    requestMock.restore();
    console.error = previousConsoleError;
    if (previousEnabled === undefined) delete process.env.HTMLTRUST_REMOTE_KEY_RESOLUTION;
    else process.env.HTMLTRUST_REMOTE_KEY_RESOLUTION = previousEnabled;
  }
});

test("direct HTTPS key documents enforce media type, kid, SPKI encoding, and lifecycle fields", async () => {
  const crypto = require("node:crypto");
  const { publicKey } = crypto.generateKeyPairSync("ed25519");
  const der = publicKey.export({ type: "spki", format: "der" });
  const encoded = der.toString("base64").replace(/=+$/, "");
  const keyid = "https://93.184.216.34/key.json";
  const valid = {
    kid: keyid,
    algorithm: "ed25519",
    publicKeyEncoding: "spki-der",
    publicKey: encoded,
    revoked: false,
  };

  const previousEnabled = process.env.HTMLTRUST_REMOTE_KEY_RESOLUTION;
  const previousConsoleError = console.error;
  let document = valid;
  let contentType = "application/htmltrust-key+json";
  const requestMock = mockHttps({
    body: () => JSON.stringify(document),
    headers: () => ({ "content-type": contentType }),
  });
  console.error = () => {};
  process.env.HTMLTRUST_REMOTE_KEY_RESOLUTION = "1";

  try {
    const resolved = await resolveKeyId(keyid);
    assert.equal(resolved.algorithm, "ed25519");
    assert.match(resolved.publicKeyPem, /BEGIN PUBLIC KEY/);

    for (const invalidDocument of [
      { ...valid, kid: "https://example.net/other.json" },
      { ...valid, publicKeyEncoding: "pem", publicKey: publicKey.export({ type: "spki", format: "pem" }) },
      { ...valid, publicKey: `${encoded}=` },
      { ...valid, expires: "tomorrow" },
      { ...valid, revoked: "false" },
    ]) {
      document = invalidDocument;
      assert.equal(await resolveKeyId(keyid), null);
    }

    document = valid;
    contentType = "text/plain";
    assert.equal(await resolveKeyId(keyid), null);

    const jwk = publicKey.export({ format: "jwk" });
    contentType = "application/jwk+json";
    document = jwk;
    assert.equal(await resolveKeyId(keyid), null, "a direct JWK without alg must fail");
    document = { ...jwk, alg: "EdDSA" };
    assert.equal((await resolveKeyId(keyid)).algorithm, "ed25519");
  } finally {
    requestMock.restore();
    console.error = previousConsoleError;
    if (previousEnabled === undefined) delete process.env.HTMLTRUST_REMOTE_KEY_RESOLUTION;
    else process.env.HTMLTRUST_REMOTE_KEY_RESOLUTION = previousEnabled;
  }
});

test("did:web resolution selects the verification method named by a fragment", async () => {
  const crypto = require("node:crypto");
  const { publicKey: first } = crypto.generateKeyPairSync("ed25519");
  const { publicKey: selected } = crypto.generateKeyPairSync("ed25519");
  const did = "did:web:93.184.216.34#key-2";
  const document = {
    id: "did:web:93.184.216.34",
    verificationMethod: [
      { id: "did:web:93.184.216.34#key-1", type: "JsonWebKey2020", publicKeyJwk: first.export({ format: "jwk" }) },
      { id: did, type: "JsonWebKey2020", publicKeyJwk: selected.export({ format: "jwk" }) },
    ],
    assertionMethod: [did],
  };
  const previousEnabled = process.env.HTMLTRUST_REMOTE_KEY_RESOLUTION;
  const requestMock = mockHttps({
    body: () => JSON.stringify(document),
    onRequest: (options) => {
      assert.equal(options.hostname, "93.184.216.34");
      assert.equal(options.path, "/.well-known/did.json");
    },
      headers: { "content-type": "application/did+json" },
  });
  process.env.HTMLTRUST_REMOTE_KEY_RESOLUTION = "1";
  try {
    const resolved = await resolveKeyId(did);
    assert.equal(
      crypto.createPublicKey(resolved.publicKeyPem).export({ type: "spki", format: "der" }).toString("hex"),
      selected.export({ type: "spki", format: "der" }).toString("hex"),
    );
  } finally {
    requestMock.restore();
    if (previousEnabled === undefined) delete process.env.HTMLTRUST_REMOTE_KEY_RESOLUTION;
    else process.env.HTMLTRUST_REMOTE_KEY_RESOLUTION = previousEnabled;
  }
});

test("did:web resolution selects a verification method compatible with the declared algorithm", async () => {
  const crypto = require("node:crypto");
  const { publicKey: ed25519 } = crypto.generateKeyPairSync("ed25519");
  const { publicKey: p256 } = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const did = "did:web:93.184.216.34";
  const document = {
    verificationMethod: [
      { id: `${did}#ed25519`, type: "JsonWebKey2020", publicKeyJwk: { ...ed25519.export({ format: "jwk" }), alg: "EdDSA" } },
      { id: `${did}#p256`, type: "JsonWebKey2020", publicKeyJwk: { ...p256.export({ format: "jwk" }), alg: "ES256" } },
    ],
    assertionMethod: [`${did}#p256`],
  };
  const previousEnabled = process.env.HTMLTRUST_REMOTE_KEY_RESOLUTION;
  const requestMock = mockHttps({
    body: () => JSON.stringify(document),
    headers: { "content-type": "application/did+json" },
  });
  process.env.HTMLTRUST_REMOTE_KEY_RESOLUTION = "1";
  try {
    const resolved = await resolveKeyId(did, { algorithm: "ecdsa-p256" });
    assert.equal(resolved.algorithm, "ecdsa-p256");
    assert.deepEqual(
      crypto.createPublicKey(resolved.publicKeyPem).export({ type: "spki", format: "der" }),
      p256.export({ type: "spki", format: "der" }),
    );
  } finally {
    requestMock.restore();
    if (previousEnabled === undefined) delete process.env.HTMLTRUST_REMOTE_KEY_RESOLUTION;
    else process.env.HTMLTRUST_REMOTE_KEY_RESOLUTION = previousEnabled;
  }
});

test("did:web resolution rejects a verification method whose type disagrees with its key", async () => {
  const crypto = require("node:crypto");
  const { publicKey } = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const did = "did:web:93.184.216.34";
  const keyid = `${did}#wrong-type`;
  const document = {
    verificationMethod: [{
      id: keyid,
      type: "Ed25519VerificationKey2020",
      publicKeyJwk: { ...publicKey.export({ format: "jwk" }), alg: "ES256" },
    }],
    assertionMethod: [keyid],
  };
  const previousEnabled = process.env.HTMLTRUST_REMOTE_KEY_RESOLUTION;
  const previousConsoleError = console.error;
  const requestMock = mockHttps({
    body: () => JSON.stringify(document),
    headers: { "content-type": "application/did+json" },
  });
  process.env.HTMLTRUST_REMOTE_KEY_RESOLUTION = "1";
  console.error = () => {};
  try {
    assert.equal(await resolveKeyId(did, { algorithm: "ecdsa-p256" }), null);
    delete document.verificationMethod[0].type;
    assert.equal(
      await resolveKeyId(did, { algorithm: "ecdsa-p256" }),
      null,
      "a DID verification method without a type must fail",
    );
  } finally {
    requestMock.restore();
    console.error = previousConsoleError;
    if (previousEnabled === undefined) delete process.env.HTMLTRUST_REMOTE_KEY_RESOLUTION;
    else process.env.HTMLTRUST_REMOTE_KEY_RESOLUTION = previousEnabled;
  }
});

test("did:web resolution rejects revoked and expired assertion methods", async () => {
  const crypto = require("node:crypto");
  const { publicKey: revoked } = crypto.generateKeyPairSync("ed25519");
  const { publicKey: expired } = crypto.generateKeyPairSync("ed25519");
  const did = "did:web:93.184.216.34";
  const revokedId = `${did}#revoked`;
  const expiredId = `${did}#expired`;
  const document = {
    verificationMethod: [
      {
        id: revokedId,
        type: "Ed25519VerificationKey2020",
        publicKeyJwk: revoked.export({ format: "jwk" }),
        revoked: true,
      },
      {
        id: expiredId,
        type: "Ed25519VerificationKey2020",
        publicKeyJwk: expired.export({ format: "jwk" }),
        expires: "2020-01-01T00:00:00Z",
      },
    ],
    assertionMethod: [revokedId, expiredId],
  };
  const previousEnabled = process.env.HTMLTRUST_REMOTE_KEY_RESOLUTION;
  const previousConsoleError = console.error;
  const requestMock = mockHttps({
    body: () => JSON.stringify(document),
    headers: { "content-type": "application/did+json" },
  });
  process.env.HTMLTRUST_REMOTE_KEY_RESOLUTION = "1";
  console.error = () => {};
  try {
    assert.equal(await resolveKeyId(did, { algorithm: "ed25519" }), null);
  } finally {
    requestMock.restore();
    console.error = previousConsoleError;
    if (previousEnabled === undefined) delete process.env.HTMLTRUST_REMOTE_KEY_RESOLUTION;
    else process.env.HTMLTRUST_REMOTE_KEY_RESOLUTION = previousEnabled;
  }
});

test("did:web resolution accepts an embedded assertion verification method", async () => {
  const crypto = require("node:crypto");
  const { publicKey } = crypto.generateKeyPairSync("ed25519");
  const did = "did:web:93.184.216.34";
  const embedded = {
    id: `${did}#embedded`,
    type: "Ed25519VerificationKey2020",
    publicKeyJwk: publicKey.export({ format: "jwk" }),
  };
  const document = { verificationMethod: [], assertionMethod: [embedded] };
  const previousEnabled = process.env.HTMLTRUST_REMOTE_KEY_RESOLUTION;
  const requestMock = mockHttps({
    body: () => JSON.stringify(document),
    headers: { "content-type": "application/did+json" },
  });
  process.env.HTMLTRUST_REMOTE_KEY_RESOLUTION = "1";
  try {
    const resolved = await resolveKeyId(did, { algorithm: "ed25519" });
    assert.equal(resolved.algorithm, "ed25519");
    assert.deepEqual(
      crypto.createPublicKey(resolved.publicKeyPem).export({ type: "spki", format: "der" }),
      publicKey.export({ type: "spki", format: "der" }),
    );
  } finally {
    requestMock.restore();
    if (previousEnabled === undefined) delete process.env.HTMLTRUST_REMOTE_KEY_RESOLUTION;
    else process.env.HTMLTRUST_REMOTE_KEY_RESOLUTION = previousEnabled;
  }
});

test("did:web resolution never falls back to an unauthorized compatible key", async () => {
  const crypto = require("node:crypto");
  const { publicKey: authorized } = crypto.generateKeyPairSync("ed25519");
  const { publicKey: unauthorized } = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const did = "did:web:93.184.216.34";
  const authorizedId = `${did}#authorized-ed25519`;
  const document = {
    verificationMethod: [
      {
        id: authorizedId,
        type: "Ed25519VerificationKey2020",
        publicKeyJwk: { ...authorized.export({ format: "jwk" }), alg: "EdDSA" },
      },
      {
        id: `${did}#unauthorized-p256`,
        type: "EcdsaSecp256r1VerificationKey2019",
        publicKeyJwk: { ...unauthorized.export({ format: "jwk" }), alg: "ES256" },
      },
    ],
    assertionMethod: [authorizedId],
  };
  const previousEnabled = process.env.HTMLTRUST_REMOTE_KEY_RESOLUTION;
  const previousConsoleError = console.error;
  const requestMock = mockHttps({
    body: () => JSON.stringify(document),
    headers: { "content-type": "application/did+json" },
  });
  process.env.HTMLTRUST_REMOTE_KEY_RESOLUTION = "1";
  console.error = () => {};
  try {
    assert.equal(await resolveKeyId(did, { algorithm: "ecdsa-p256" }), null);
  } finally {
    requestMock.restore();
    console.error = previousConsoleError;
    if (previousEnabled === undefined) delete process.env.HTMLTRUST_REMOTE_KEY_RESOLUTION;
    else process.env.HTMLTRUST_REMOTE_KEY_RESOLUTION = previousEnabled;
  }
});

test("remote key resolution pins the validated DNS address for the HTTPS request", async () => {
  const previousEnabled = process.env.HTMLTRUST_REMOTE_KEY_RESOLUTION;
  const previousLookup = dns.lookup;
  const pinnedAddress = "93.184.216.34";
  let lookups = 0;
  dns.lookup = async () => {
    lookups += 1;
    return [{ address: pinnedAddress, family: 4 }];
  };
  const requestMock = mockHttps({
    body: "{}",
    headers: { "content-type": "application/json" },
    onRequest: (options) => {
      options.lookup(options.hostname, {}, (error, address, family) => {
        assert.ifError(error);
        assert.equal(address, pinnedAddress);
        assert.equal(family, 4);
      });
      options.lookup(options.hostname, { all: true }, (error, addresses) => {
        assert.ifError(error);
        assert.deepEqual(addresses, [{ address: pinnedAddress, family: 4 }]);
      });
    },
  });
  process.env.HTMLTRUST_REMOTE_KEY_RESOLUTION = "1";
  try {
    assert.equal(await resolveKeyId("https://rebind.example.test/key.json"), null);
    assert.equal(lookups, 1);
  } finally {
    requestMock.restore();
    dns.lookup = previousLookup;
    if (previousEnabled === undefined) delete process.env.HTMLTRUST_REMOTE_KEY_RESOLUTION;
    else process.env.HTMLTRUST_REMOTE_KEY_RESOLUTION = previousEnabled;
  }
});
