const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("crypto");

const Key = require("../src/models/Key");
const ContentSignature = require("../src/models/ContentSignature");
const ContentOccurrence = require("../src/models/ContentOccurrence");
const Author = require("../src/models/Author");
const contentController = require("../src/controllers/contentController");
const { protectWithAuthorApiKey } = require("../src/middleware/auth");
const { buildV1ContentSigningPayload, PROFILE } = require("../src/utils/signingProfile");
const { verifySignature } = require("../src/utils/crypto");

const requestBody = () => ({
  contentHash: "sha256:IVAwpRTDujszmYf76W497alVTtxGCgtJtQlasiFSCM8",
  sourceURL: "HTTPS://EXAMPLE.COM:443/essays/engines#analysis",
  scope: "url",
  signedAt: "2026-01-15T12:00:00Z",
  claims: [
    { name: "author", content: "Ada Lovelace" },
    { name: "signed-at", content: "2026-01-15T12:00:00Z" },
  ],
});

const response = () => {
  const result = {};
  return {
    result,
    status(code) { result.status = code; return this; },
    type() { return this; },
    json(body) { result.body = body; return this; },
    set() { return this; },
  };
};

test("author convenience signing returns and stores a complete v1 section", async () => {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519", {
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
    publicKeyEncoding: { type: "spki", format: "pem" },
  });
  const authorId = "507f1f77bcf86cd799439011";
  const keyId = "507f1f77bcf86cd799439012";
  const key = {
    _id: keyId,
    authorId,
    algorithm: "ed25519",
    publicKey,
    privateKey,
  };
  const stored = [];
  const occurrences = [];
  let keySort;
  const original = {
    findOne: Key.findOne,
    signatureFindOne: ContentSignature.findOne,
    signatureCreate: ContentSignature.create,
    occurrenceUpsert: ContentOccurrence.findOneAndUpdate,
  };
  try {
    Key.findOne = () => ({
      sort(value) { keySort = value; return this; },
      select: async () => key,
    });
    ContentSignature.findOne = async () => null;
    ContentSignature.create = async (document) => {
      const record = { ...document, _id: "507f1f77bcf86cd799439013", createdAt: new Date("2026-01-15T12:00:00Z") };
      stored.push(record);
      return record;
    };
    ContentOccurrence.findOneAndUpdate = async (identity, update) => {
      occurrences.push({ identity, update });
      return update;
    };

    const req = {
      protocol: "https",
      get(name) { return name.toLowerCase() === "host" ? "directory.example" : undefined; },
      body: requestBody(),
      author: { _id: authorId },
    };
    const res = response();
    await contentController.signContent(req, res);

    assert.equal(res.result.status, 201);
    const output = res.result.body;
    assert.equal(output.profile, PROFILE.signature);
    assert.equal(output.scope, "url");
    assert.equal(output.location, "https://example.com/essays/engines");
    assert.equal(output.keyid, "https://directory.example/keys/507f1f77bcf86cd799439012");
    assert.equal(output.algorithm, "ed25519");
    assert.equal(output.claimsHash, "sha256:Y1i6VMTgz6hx2A3DEuoqOD4N2otfZwlKj/tJQQglHIQ");
    assert.deepEqual(keySort, { createdAt: -1, _id: -1 });
    assert.equal(stored.length, 1);
    assert.equal(stored[0].profile, PROFILE.signature);
    assert.equal(stored[0].location, output.location);
    assert.equal(occurrences.length, 1);
    assert.equal(occurrences[0].identity.url, requestBody().sourceURL);

    const prepared = await buildV1ContentSigningPayload({
      ...requestBody(),
      profile: PROFILE.signature,
      keyid: output.keyid,
      algorithm: output.algorithm,
      location: output.location,
    });
    assert.equal(verifySignature(prepared.payload, output.signature, publicKey, "ed25519"), true);
  } finally {
    Key.findOne = original.findOne;
    ContentSignature.findOne = original.signatureFindOne;
    ContentSignature.create = original.signatureCreate;
    ContentOccurrence.findOneAndUpdate = original.occurrenceUpsert;
  }
});

test("author convenience signing rejects the removed colon-binding fields", async () => {
  const res = response();
  await contentController.signContent({
    body: { ...requestBody(), domain: "https://example.com" },
    author: { _id: "507f1f77bcf86cd799439011" },
  }, res);
  assert.equal(res.result.status, 400);
  assert.match(res.result.body.detail, /domain is not accepted/);
});

test("author convenience signing returns an RFC 9457 problem when no active key exists", async () => {
  const originalFindOne = Key.findOne;
  try {
    Key.findOne = () => ({
      sort() { return this; },
      select: async () => null,
    });
    const res = response();
    await contentController.signContent({
      body: requestBody(),
      author: { _id: "507f1f77bcf86cd799439011" },
    }, res);
    assert.equal(res.result.status, 404);
    assert.equal(res.result.body.type, "https://htmltrust.org/errors/signing-key-not-found");
    assert.equal(res.result.body.status, 404);
  } finally {
    Key.findOne = originalFindOne;
  }
});

test("author convenience signing treats an identical retry as immutable and idempotent", async () => {
  const { privateKey } = crypto.generateKeyPairSync("ed25519", {
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
    publicKeyEncoding: { type: "spki", format: "pem" },
  });
  const authorId = "507f1f77bcf86cd799439021";
  const key = {
    _id: "507f1f77bcf86cd799439022",
    authorId,
    algorithm: "ed25519",
    privateKey,
  };
  const body = requestBody();
  const keyid = "https://directory.example/keys/507f1f77bcf86cd799439022";
  const location = "https://example.com/essays/engines";
  const prepared = await buildV1ContentSigningPayload({
    ...body,
    profile: PROFILE.signature,
    keyid,
    algorithm: "ed25519",
    location,
  });
  const existing = {
    _id: "507f1f77bcf86cd799439023",
    profile: PROFILE.signature,
    algorithm: "ed25519",
    claimsHash: prepared.claimsHash,
    signedAt: prepared.signedAt,
    scope: prepared.scope,
    signature: require("../src/utils/crypto").signContent(prepared.payload, privateKey, "ed25519"),
    createdAt: new Date("2026-01-15T12:00:00Z"),
    occurrences: 4,
  };
  const original = {
    keyFindOne: Key.findOne,
    signatureFindOne: ContentSignature.findOne,
    signatureCreate: ContentSignature.create,
    occurrenceUpsert: ContentOccurrence.findOneAndUpdate,
  };
  let createCalls = 0;
  try {
    Key.findOne = () => ({ sort() { return this; }, select: async () => key });
    ContentSignature.findOne = async () => existing;
    ContentSignature.create = async () => { createCalls += 1; throw new Error("must not create on retry"); };
    ContentOccurrence.findOneAndUpdate = async () => existing;
    const res = response();
    await contentController.signContent({
      protocol: "https",
      get(name) { return name.toLowerCase() === "host" ? "directory.example" : undefined; },
      body,
      author: { _id: authorId },
    }, res);
    assert.equal(res.result.status, 201);
    assert.equal(createCalls, 0);
    assert.equal(existing.occurrences, 4);
    assert.equal(res.result.body.signature, existing.signature);
  } finally {
    Key.findOne = original.keyFindOne;
    ContentSignature.findOne = original.signatureFindOne;
    ContentSignature.create = original.signatureCreate;
    ContentOccurrence.findOneAndUpdate = original.occurrenceUpsert;
  }
});

test("author convenience signing rejects a changed payload for an existing v1 identity", async () => {
  const { privateKey } = crypto.generateKeyPairSync("ed25519", {
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
    publicKeyEncoding: { type: "spki", format: "pem" },
  });
  const authorId = "507f1f77bcf86cd799439031";
  const key = {
    _id: "507f1f77bcf86cd799439032",
    authorId,
    algorithm: "ed25519",
    privateKey,
  };
  const body = requestBody();
  const keyid = "https://directory.example/keys/507f1f77bcf86cd799439032";
  const prepared = await buildV1ContentSigningPayload({
    ...body,
    profile: PROFILE.signature,
    keyid,
    algorithm: "ed25519",
    location: "https://example.com/essays/engines",
  });
  const original = {
    keyFindOne: Key.findOne,
    signatureFindOne: ContentSignature.findOne,
    occurrenceUpsert: ContentOccurrence.findOneAndUpdate,
  };
  try {
    Key.findOne = () => ({ sort() { return this; }, select: async () => key });
    ContentSignature.findOne = async () => ({
      profile: PROFILE.signature,
      algorithm: "ed25519",
      claimsHash: "sha256:changed",
      signedAt: prepared.signedAt,
      scope: prepared.scope,
      signature: "old-signature",
    });
    ContentOccurrence.findOneAndUpdate = async () => null;
    const res = response();
    await contentController.signContent({
      protocol: "https",
      get(name) { return name.toLowerCase() === "host" ? "directory.example" : undefined; },
      body,
      author: { _id: authorId },
    }, res);
    assert.equal(res.result.status, 409);
    assert.equal(res.result.body.type, "https://htmltrust.org/errors/content-signature-conflict");
  } finally {
    Key.findOne = original.keyFindOne;
    ContentSignature.findOne = original.signatureFindOne;
    ContentOccurrence.findOneAndUpdate = original.occurrenceUpsert;
  }
});

test("author convenience signing recovers an identical first-submit race", async () => {
  const { privateKey } = crypto.generateKeyPairSync("ed25519", {
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
    publicKeyEncoding: { type: "spki", format: "pem" },
  });
  const authorId = "507f1f77bcf86cd799439061";
  const key = {
    _id: "507f1f77bcf86cd799439062",
    authorId,
    algorithm: "ed25519",
    privateKey,
  };
  const body = requestBody();
  const keyid = "https://directory.example/keys/507f1f77bcf86cd799439062";
  const prepared = await buildV1ContentSigningPayload({
    ...body,
    profile: PROFILE.signature,
    keyid,
    algorithm: "ed25519",
    location: "https://example.com/essays/engines",
  });
  const signature = require("../src/utils/crypto").signContent(prepared.payload, privateKey, "ed25519");
  const winner = {
    _id: "507f1f77bcf86cd799439063",
    profile: PROFILE.signature,
    algorithm: "ed25519",
    claimsHash: prepared.claimsHash,
    signedAt: prepared.signedAt,
    scope: prepared.scope,
    signature,
    createdAt: new Date("2026-01-15T12:00:00Z"),
  };
  const original = {
    keyFindOne: Key.findOne,
    signatureFindOne: ContentSignature.findOne,
    signatureCreate: ContentSignature.create,
    occurrenceUpsert: ContentOccurrence.findOneAndUpdate,
  };
  let reads = 0;
  try {
    Key.findOne = () => ({ sort() { return this; }, select: async () => key });
    ContentSignature.findOne = async () => {
      reads += 1;
      return reads === 1 ? null : winner;
    };
    ContentSignature.create = async () => {
      const error = new Error("duplicate v1 identity");
      error.code = 11000;
      throw error;
    };
    ContentOccurrence.findOneAndUpdate = async () => winner;
    const res = response();
    await contentController.signContent({
      protocol: "https",
      get(name) { return name.toLowerCase() === "host" ? "directory.example" : undefined; },
      body,
      author: { _id: authorId },
    }, res);
    assert.equal(res.result.status, 201);
    assert.equal(reads, 2);
    assert.equal(res.result.body.signature, signature);
  } finally {
    Key.findOne = original.keyFindOne;
    ContentSignature.findOne = original.signatureFindOne;
    ContentSignature.create = original.signatureCreate;
    ContentOccurrence.findOneAndUpdate = original.occurrenceUpsert;
  }
});

test("author API middleware attaches the author identity used by the signer route", async () => {
  const originalFindOne = Author.findOne;
  let nextCalls = 0;
  try {
    Author.findOne = async () => ({ _id: "507f1f77bcf86cd799439041" });
    const req = {
      params: {},
      header(name) { return name === "X-AUTHOR-API-KEY" ? "author-secret" : undefined; },
    };
    const result = {};
    const res = {
      set() { return this; },
      status(code) { result.status = code; return this; },
      type() { return this; },
      json(body) { result.body = body; return this; },
    };
    await protectWithAuthorApiKey(req, res, () => { nextCalls += 1; });
    assert.equal(nextCalls, 1);
    assert.equal(req.author._id, "507f1f77bcf86cd799439041");
    assert.equal(result.status, undefined);
  } finally {
    Author.findOne = originalFindOne;
  }
});

test("v1 content signature claims hydrate as a Mongoose Map", () => {
  const record = ContentSignature.hydrate({
    contentHash: "sha256:IVAwpRTDujszmYf76W497alVTtxGCgtJtQlasiFSCM8",
    profile: PROFILE.signature,
    location: "https://example.com/essays/engines",
    keyid: "https://directory.example/keys/507f1f77bcf86cd799439052",
    claimsHash: "sha256:Y1i6VMTgz6hx2A3DEuoqOD4N2otfZwlKj/tJQQglHIQ",
    signedAt: "2026-01-15T12:00:00Z",
    signature: "signature",
    claims: { author: "Ada Lovelace" },
  });
  assert.equal(record.claims.get("author"), "Ada Lovelace");
});
