const test = require("node:test");
const assert = require("node:assert/strict");
const {
  canonicalizeEndorsement,
  safeSearchRegex,
} = require("../src/utils/htmltrustProtocol");
const { canonicalizeClaims } = require("../src/utils/claims");
const { validateEndorsementDocument } = require("../src/controllers/endorsementController");

test("safeSearchRegex turns caller input into a literal", () => {
  // Every one of these is regular-expression syntax that used to reach the
  // database verbatim through { $regex: userInput }.
  const hostile = ".*|^$(a)[b]{1,2}?+\\";
  const filter = safeSearchRegex(hostile, "name");
  assert.equal(filter.$options, "i");
  // The escaped pattern matches the literal text and nothing else.
  assert.ok(new RegExp(filter.$regex, "i").test(hostile));
  assert.ok(!new RegExp(filter.$regex, "i").test("anything else"));
});

test("safeSearchRegex neutralizes the classic backtracking bomb", () => {
  const bomb = "(a+)+$";
  const filter = safeSearchRegex(bomb, "name");
  const pattern = new RegExp(filter.$regex, "i");
  const start = Date.now();
  // Against the unescaped pattern this input backtracks for minutes.
  pattern.test("a".repeat(40) + "!");
  assert.ok(Date.now() - start < 100);
});

test("safeSearchRegex caps the input length", () => {
  assert.throws(() => safeSearchRegex("x".repeat(129), "name"), /128 characters or fewer/);
  assert.doesNotThrow(() => safeSearchRegex("x".repeat(128), "name"));
});

test("safeSearchRegex anchors the match", () => {
  assert.ok(safeSearchRegex("Alice", "name").$regex.startsWith("^"));
});

test("the endorsement payload omits only the signature", () => {
  const document = {
    endorser: "did:web:reviewer.example",
    endorsement: "sha256:AAAA",
    algorithm: "ed25519",
    timestamp: "2026-05-10T09:00:00Z",
    signature: "ignored",
    // Draft 10.1: unrecognised members MUST be part of the signed payload.
    somethingNew: { nested: [1, 2] },
  };
  const payload = canonicalizeEndorsement(document);
  assert.ok(!payload.includes("signature"));
  assert.ok(payload.includes("somethingNew"));
  assert.equal(
    payload,
    '{"algorithm":"ed25519","endorsement":"sha256:AAAA","endorser":"did:web:reviewer.example",' +
      '"somethingNew":{"nested":[1,2]},"timestamp":"2026-05-10T09:00:00Z"}',
  );
});

test("canonical endorsement validation preserves every extension member", () => {
  const document = {
    endorser: "did:web:reviewer.example",
    endorsement: `sha256:${Buffer.alloc(32).toString("base64").replace(/=+$/, "")}`,
    algorithm: "ed25519",
    timestamp: "2026-05-10T09:00:00Z",
    signature: Buffer.alloc(64).toString("base64").replace(/=+$/, ""),
    rawBlob: { extension: true },
  };
  assert.deepEqual(validateEndorsementDocument(document).rawBlob, { extension: true });
  assert.equal(
    Object.hasOwn(validateEndorsementDocument(document, { stripLegacyRawBlob: true }), "rawBlob"),
    false,
  );
});

test("claims canonicalization sorts by name in UTF-8 byte order", async () => {
  // "z" (U+007A) sorts before the astral character in UTF-8 byte order, and
  // the whole-line sort the previous implementation used would have ordered
  // these by value rather than by name.
  const canonical = await canonicalizeClaims({
    z: "aaa",
    a: "zzz",
    "signed-at": "2026-05-12T12:00:00Z",
  });
  assert.equal(canonical, "a:zzz\nsigned-at:2026-05-12T12\\:00\\:00Z\nz:aaa\n");
});

test("claims canonicalization normalizes claim text", async () => {
  // Draft 4.4 normalization: NFKC plus whitespace collapse. Without it the
  // directory computes a different claims hash than the signer did.
  const canonical = await canonicalizeClaims({ "  License  ": "CC-BY   4.0" });
  assert.equal(canonical, "License:CC-BY 4.0\n");
});

test("claims canonicalization removes boundary whitespace from names and values", async () => {
  const canonical = await canonicalizeClaims([{ name: " author ", content: " Ada Lovelace " }]);
  assert.equal(canonical, "author:Ada Lovelace\n");
});

test("claims canonicalization rejects duplicate normalized names", async () => {
  await assert.rejects(
    () => canonicalizeClaims([{ name: "a", content: "1" }, { name: "a", content: "2" }]),
    /claim-duplicate/,
  );
});
