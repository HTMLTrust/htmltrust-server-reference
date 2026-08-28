const test = require("node:test");
const assert = require("node:assert/strict");
const {
  assertV1Timestamp,
  deriveLocation,
  PROFILE,
  validateV1ContentSubmission,
} = require("../src/utils/signingProfile");
const { canonicalizeClaims } = require("../src/utils/claims");

const vectorSubmission = () => ({
  profile: PROFILE.signature,
  contentHash: "sha256:IVAwpRTDujszmYf76W497alVTtxGCgtJtQlasiFSCM8",
  keyid: "https://keys.example/alice-2026.json",
  algorithm: "ed25519",
  signedAt: "2026-01-15T12:00:00Z",
  scope: "url",
  location: "https://example.com/essays/engines",
  signature: "m0ykSPqUWdyZprUAqosOB2IEK2XsKp7auPIWz80/2ht+LwT1LiNcsLL6cn2IkmTZFG9ptLiUHaB1crPJgBw7BA",
  sourceURL: "HTTPS://EXAMPLE.COM:443/essays/engines#analysis",
  claims: [
    { name: "author", content: "Ada Lovelace" },
    { name: "claim:License", content: "CC-BY-4.0" },
    { name: "signed-at", content: "2026-01-15T12:00:00Z" },
  ],
});

test("constructs the frozen signing-profile vector", async () => {
  const validated = await validateV1ContentSubmission(vectorSubmission());
  assert.equal(
    validated.canonicalClaims,
    "author:Ada Lovelace\nclaim\\:License:CC-BY-4.0\nsigned-at:2026-01-15T12\\:00\\:00Z\n",
  );
  assert.equal(
    validated.claimsHash,
    "sha256:Fk5udwCnu1au8v5oaBsU+aSB5S2zSLqoF0xXO6HrIn4",
  );
  assert.equal(
    validated.payload,
    '{"algorithm":"ed25519","attributeProfile":"htmltrust-attrs-v1",' +
      '"canonicalizationProfile":"htmltrust-c14n-v1",' +
      '"claimsHash":"sha256:Fk5udwCnu1au8v5oaBsU+aSB5S2zSLqoF0xXO6HrIn4",' +
      '"contentHash":"sha256:IVAwpRTDujszmYf76W497alVTtxGCgtJtQlasiFSCM8",' +
      '"context":"https://htmltrust.org/protocol/signed-section",' +
      '"keyid":"https://keys.example/alice-2026.json",' +
      '"location":"https://example.com/essays/engines",' +
      '"profile":"htmltrust-signature-v1","scope":"url",' +
      '"signedAt":"2026-01-15T12:00:00Z","urlProfile":"htmltrust-safe-url-v1"}',
  );
});

test("derives exact URL and origin scope from an HTTPS source URL", () => {
  assert.equal(
    deriveLocation("https://BÜCHER.example:443/article?q=1#part", "url"),
    "https://xn--bcher-kva.example/article?q=1",
  );
  assert.equal(
    deriveLocation("https://example.org:8443/a?q=1#part", "origin"),
    "https://example.org:8443",
  );
});

test("rejects non-public v1 locations and hidden URL controls", () => {
  assert.throws(() => deriveLocation("http://example.com/a", "url"), /HTTPS/);
  assert.throws(() => deriveLocation("https://user@example.com/a", "url"), /credentials/);
  assert.throws(() => deriveLocation("https://example.com/\tpath", "url"), /control/);
  assert.throws(() => deriveLocation("https://example.com/a", "path"), /scope/);
});

test("accepts only the exact v1 timestamp grammar and valid calendar dates", () => {
  assert.equal(assertV1Timestamp("2024-02-29T23:59:59Z"), "2024-02-29T23:59:59Z");
  for (const value of [
    "0000-01-01T00:00:00Z",
    "2023-02-29T00:00:00Z",
    "2026-01-15t12:00:00z",
    "2026-01-15T12:00:00.000Z",
    "2026-01-15T12:00:60Z",
    "2026-01-15T12:00:00+00:00",
  ]) {
    assert.throws(() => assertV1Timestamp(value));
  }
});

test("claims escaping is injective and applies after normalization", async () => {
  assert.equal(
    await canonicalizeClaims([
      { name: "a:b\\c", content: "x:y\\z" },
      { name: "signed-at", content: "2026-01-15T12:00:00Z" },
    ], { strictArray: true }),
    "a\\:b\\\\c:x\\:y\\\\z\nsigned-at:2026-01-15T12\\:00\\:00Z\n",
  );
});

test("rejects incomplete, duplicate, oversized, or caller-hashed claims", async () => {
  const suppliedHash = { ...vectorSubmission(), claimsHash: "sha256:ignored" };
  await assert.rejects(() => validateV1ContentSubmission(suppliedHash), /must not be submitted/);

  const duplicate = vectorSubmission();
  duplicate.claims = [...duplicate.claims, { name: "author", content: "Other" }];
  await assert.rejects(() => validateV1ContentSubmission(duplicate), /claim-duplicate/);

  const missingTimestamp = vectorSubmission();
  missingTimestamp.claims = missingTimestamp.claims.filter(({ name }) => name !== "signed-at");
  await assert.rejects(() => validateV1ContentSubmission(missingTimestamp), /exactly one signed-at/);

  const extraMember = vectorSubmission();
  extraMember.claims = [{ name: "signed-at", content: extraMember.signedAt, extra: true }];
  await assert.rejects(() => validateV1ContentSubmission(extraMember), /only name and content/);

  const tooMany = vectorSubmission();
  tooMany.claims = Array.from({ length: 65 }, (_, index) => ({
    name: index === 0 ? "signed-at" : `claim-${index}`,
    content: index === 0 ? tooMany.signedAt : "value",
  }));
  await assert.rejects(() => validateV1ContentSubmission(tooMany), /resource-limit-exceeded/);
});

test("rejects a location or signed-at claim that does not match the body", async () => {
  const wrongLocation = { ...vectorSubmission(), location: "https://example.com/other" };
  await assert.rejects(() => validateV1ContentSubmission(wrongLocation), /derived from sourceURL/);

  const wrongTime = vectorSubmission();
  wrongTime.claims = wrongTime.claims.map((claim) => (
    claim.name === "signed-at" ? { ...claim, content: "2026-01-15T12:00:01Z" } : claim
  ));
  await assert.rejects(() => validateV1ContentSubmission(wrongTime), /must equal signedAt/);
});
