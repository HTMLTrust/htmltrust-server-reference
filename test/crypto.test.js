const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const {
  generateKeyPair,
  signContent,
  verifySignature,
} = require("../src/utils/crypto");

for (const [algorithm, expectedBytes] of [
  ["ecdsa-p256", 64],
  ["ecdsa-p384", 96],
]) {
  test(`${algorithm} uses fixed-width IEEE P1363 signatures`, () => {
    const { publicKey, privateKey } = generateKeyPair(algorithm);
    const signature = signContent("wire-format", privateKey, algorithm);
    assert.equal(Buffer.from(signature, "base64").byteLength, expectedBytes);
    assert.equal(verifySignature("wire-format", signature, publicKey, algorithm), true);
    assert.equal(verifySignature("tampered", signature, publicKey, algorithm), false);
  });
}

test("registry ECDSA algorithms reject DER signatures", () => {
  const { publicKey, privateKey } = generateKeyPair("ecdsa-p256");
  const der = crypto.sign("sha256", Buffer.from("wire-format"), privateKey)
    .toString("base64")
    .replace(/=+$/, "");
  assert.equal(verifySignature("wire-format", der, publicKey, "ecdsa-p256"), false);
});
