const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const { keyDocumentFor } = require("../src/utils/htmltrustProtocol");

test("directory key documents expose canonical SPKI DER and lifecycle metadata", () => {
  const { publicKey } = crypto.generateKeyPairSync("ed25519", {
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  const key = {
    _id: "abc123",
    publicKey,
    algorithm: "ed25519",
    revoked: true,
    revokedAt: new Date("2026-08-01T00:00:00Z"),
    expiresAt: new Date("2026-12-31T00:00:00Z"),
    supersededBy: "https://directory.example/keys/new",
    previousKeys: ["https://directory.example/keys/older"],
  };
  const kid = "https://directory.example/keys/abc123";
  const document = keyDocumentFor(key, kid);

  assert.equal(document.kid, kid);
  assert.equal(document.algorithm, "ed25519");
  assert.equal(document.publicKeyEncoding, "spki-der");
  assert.equal(document.revoked, true);
  assert.equal(document.revokedAt, "2026-08-01T00:00:00.000Z");
  assert.equal(document.expires, "2026-12-31T00:00:00.000Z");
  assert.equal(document.supersededBy, "https://directory.example/keys/new");
  assert.deepEqual(document.previousKeys, ["https://directory.example/keys/older"]);
  assert.equal(document.publicKeyPem, undefined);
  assert.ok(!document.publicKey.includes("="));

  const decoded = Buffer.from(document.publicKey, "base64");
  assert.equal(
    crypto.createPublicKey({ key: decoded, format: "der", type: "spki" })
      .export({ type: "spki", format: "pem" }),
    publicKey,
  );
});
