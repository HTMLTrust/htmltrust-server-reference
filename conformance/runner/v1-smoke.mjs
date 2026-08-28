#!/usr/bin/env node

import {
  createHash,
  generateKeyPairSync,
  sign as cryptoSign,
} from "node:crypto";

const target = (process.argv[2] || "http://localhost:3000").replace(/\/$/, "");
const generalApiKey = process.argv[3] || process.env.GENERAL_API_KEY || "conformance_general_key";

const fail = (message, detail) => {
  if (detail !== undefined) console.error(detail);
  throw new Error(message);
};

const requestJson = async (url, init = {}, expectedStatus = 200) => {
  const response = await fetch(url, init);
  const text = await response.text();
  let body;
  try {
    body = text ? JSON.parse(text) : undefined;
  } catch {
    body = text;
  }
  if (response.status !== expectedStatus) {
    fail(`${init.method || "GET"} ${url} returned ${response.status}, expected ${expectedStatus}`, body);
  }
  return { response, body };
};

const assertMediaType = ({ response }, expected, label) => {
  const contentType = response.headers.get("content-type") || "";
  if (!contentType.startsWith(expected)) {
    fail(`${label} returned ${contentType}, expected ${expected}`);
  }
};

const canonicalize = (value) => {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(",")}]`;
  return `{${Object.keys(value)
    .sort((left, right) => (left === right ? 0 : left < right ? -1 : 1))
    .map((key) => `${JSON.stringify(key)}:${canonicalize(value[key])}`)
    .join(",")}}`;
};

const unpadded = (buffer) => buffer.toString("base64").replace(/=+$/, "");
const prefixedSha256 = (text) => `sha256:${unpadded(createHash("sha256").update(text).digest())}`;

const signHttpRequest = ({
  url,
  body,
  keyid,
  privateKey,
  nonce,
  components = ["@method", "@target-uri", "host", "date", "content-digest"],
  label = "sig1",
  includeAlg = true,
  padded = false,
}) => {
  const parsed = new URL(url);
  const date = new Date().toUTCString();
  const created = Math.floor(Date.now() / 1000);
  const digest = createHash("sha256").update(body).digest("base64");
  const contentDigest = `sha-256=:${digest}:`;
  const parameters =
    `(${components.map((component) => `"${component}"`).join(" ")})` +
    `;created=${created};keyid="${keyid}"` +
    (includeAlg ? `;alg="ed25519"` : "") +
    `;nonce="${nonce}"`;
  const values = {
    "@method": "POST",
    "@target-uri": url,
    host: parsed.host,
    date,
    "content-digest": contentDigest,
    "content-type": "application/json",
    "@request-target": parsed.pathname + parsed.search,
  };
  const base = [
    ...components.map((component) => `"${component}": ${values[component]}`),
    `"@signature-params": ${parameters}`,
  ].join("\n");
  let signature = cryptoSign(null, Buffer.from(base, "utf8"), privateKey).toString("base64");
  if (!padded) signature = unpadded(Buffer.from(signature, "base64"));
  return {
    "content-type": "application/json",
    host: parsed.host,
    date,
    "content-digest": contentDigest,
    "signature-input": `${label}=${parameters}`,
    signature: `${label}=:${signature}${padded ? "=" : ""}:`,
  };
};

const signedPost = async ({ path, document, keyid, privateKey, nonce, expectedStatus = 201 }) => {
  const url = `${target}${path}`;
  const body = JSON.stringify(document);
  return requestJson(url, {
    method: "POST",
    headers: signHttpRequest({ url, body, keyid, privateKey, nonce }),
    body,
  }, expectedStatus);
};

const main = async () => {
  const signingKey = generateKeyPairSync("ed25519", {
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });

  const author = await requestJson(`${target}/api/authors`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-api-key": generalApiKey,
    },
    body: JSON.stringify({
      name: `V1 smoke ${Date.now()}`,
      keyType: "ORGANIZATION",
      keyAlgorithm: "ed25519",
      publicKey: signingKey.publicKey,
    }),
  }, 201);
  const authorId = author.body.author.id;
  const publicKey = await requestJson(`${target}/api/authors/${authorId}/public-key`);
  const keyId = publicKey.body.id || publicKey.body._id;
  const keyid = `${target}/keys/${keyId}`;

  const discovery = await requestJson(`${target}/.well-known/htmltrust`);
  assertMediaType(discovery, "application/htmltrust-directory+json", "discovery");
  if (!discovery.body.supportedProfiles?.includes("htmltrust-signature-v1")) {
    fail("discovery does not advertise htmltrust-signature-v1", discovery.body);
  }
  if (discovery.body.directory !== `${target}/`) {
    fail("discovery directory does not name the canonical root", discovery.body);
  }
  await requestJson(`${target}/endorsements?content-hash=sha256:removed-root-list-route`, {}, 404);
  await requestJson(`${target}/endorsements/000000000000000000000000`, { method: "DELETE" }, 404);

  const keyDocument = await requestJson(keyid);
  assertMediaType(keyDocument, "application/htmltrust-key+json", "key document");
  if (keyDocument.body.kid !== keyid || keyDocument.body.publicKeyPem !== undefined) {
    fail("root key document has the wrong kid or exposes the PEM compatibility field", keyDocument.body);
  }
  const reputation = await requestJson(
    `${target}/signers/${encodeURIComponent(keyId)}/reputation`,
  );
  assertMediaType(reputation, "application/json", "signer reputation");
  if (reputation.body.keyid !== keyId || typeof reputation.body.score !== "number") {
    fail("root signer reputation has the wrong key identifier or score", reputation.body);
  }

  const signedAt = "2026-01-15T12:00:00Z";
  const claims = [
    { name: "author", content: "Ada Lovelace" },
    { name: "claim:License", content: "CC-BY-4.0" },
    { name: "signed-at", content: signedAt },
  ];
  const canonicalClaims =
    "author:Ada Lovelace\nclaim\\:License:CC-BY-4.0\nsigned-at:2026-01-15T12\\:00\\:00Z\n";
  const contentHash = prefixedSha256("HTMLTrust v1 integration content");
  const claimsHash = prefixedSha256(canonicalClaims);
  const location = "https://example.com/research/paper?revision=1";
  const signingObject = {
    algorithm: "ed25519",
    attributeProfile: "htmltrust-attrs-v1",
    canonicalizationProfile: "htmltrust-c14n-v1",
    claimsHash,
    contentHash,
    context: "https://htmltrust.org/protocol/signed-section",
    keyid,
    location,
    profile: "htmltrust-signature-v1",
    scope: "url",
    signedAt,
    urlProfile: "htmltrust-safe-url-v1",
  };
  const contentSignature = unpadded(cryptoSign(
    null,
    Buffer.from(canonicalize(signingObject), "utf8"),
    signingKey.privateKey,
  ));
  const submission = {
    profile: "htmltrust-signature-v1",
    contentHash,
    keyid,
    algorithm: "ed25519",
    signedAt,
    scope: "url",
    location,
    signature: contentSignature,
    sourceURL: `${location}#results`,
    claims,
  };

  const submitted = await signedPost({
    path: "/content",
    document: submission,
    keyid,
    privateKey: signingKey.privateKey,
    nonce: "content-valid",
  });
  assertMediaType(submitted, "application/htmltrust-content+json", "content submission");
  if (submitted.response.headers.get("location") !== `/content/${encodeURIComponent(contentHash)}`) {
    fail("POST /content returned the wrong Location header", submitted.response.headers.get("location"));
  }
  const signer = submitted.body.signers?.[0];
  if (
    signer?.profile !== "htmltrust-signature-v1" ||
    signer?.keyid !== keyid ||
    signer?.location !== location ||
    signer?.scope !== "url"
  ) {
    fail("POST /content returned an incomplete v1 signer record", submitted.body);
  }

  const content = await requestJson(`${target}/content/${encodeURIComponent(contentHash)}`);
  assertMediaType(content, "application/htmltrust-content+json", "content record");

  const badLocation = { ...submission, location: "https://example.com/research/other" };
  const rejectedLocation = await signedPost({
    path: "/content",
    document: badLocation,
    keyid,
    privateKey: signingKey.privateKey,
    nonce: "content-bad-location",
    expectedStatus: 400,
  });
  if (rejectedLocation.body.type !== "https://htmltrust.org/errors/content-submission-invalid") {
    fail("POST /content did not reject a mismatched location with problem details", rejectedLocation.body);
  }

  const apiKeyOnly = await requestJson(`${target}/content`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-api-key": generalApiKey,
    },
    body: JSON.stringify(submission),
  }, 401);
  if (!apiKeyOnly.response.headers.get("www-authenticate")) {
    fail("canonical POST /content accepted API-key fallback or omitted its signature challenge");
  }

  const submissionBody = JSON.stringify(submission);
  const signatureProfileCases = [
    {
      name: "legacy request-target component",
      components: ["@method", "@request-target", "host", "date", "content-digest"],
      nonce: "content-legacy-target",
    },
    {
      name: "reordered components",
      components: ["@target-uri", "@method", "host", "date", "content-digest"],
      nonce: "content-reordered-components",
    },
    {
      name: "wrong signature label",
      label: "other",
      nonce: "content-wrong-label",
    },
    {
      name: "missing alg parameter",
      includeAlg: false,
      nonce: "content-missing-alg",
    },
    {
      name: "additional covered component",
      components: ["@method", "@target-uri", "host", "date", "content-digest", "content-type"],
      nonce: "content-additional-component",
    },
    {
      name: "padded signature bytes",
      padded: true,
      nonce: "content-padded-signature",
    },
  ];
  for (const profileCase of signatureProfileCases) {
    const rejected = await requestJson(`${target}/content`, {
      method: "POST",
      headers: signHttpRequest({
        url: `${target}/content`,
        body: submissionBody,
        keyid,
        privateKey: signingKey.privateKey,
        ...profileCase,
      }),
      body: submissionBody,
    }, 401);
    if (!rejected.response.headers.get("www-authenticate")) {
      fail(`canonical POST /content accepted ${profileCase.name}`);
    }
  }

  const unsignedEndorsement = {
    endorser: keyid,
    endorsement: contentHash,
    algorithm: "ed25519",
    timestamp: "2026-05-10T09:00:00Z",
    claim: "Reviewed against the published source.",
  };
  const endorsement = {
    ...unsignedEndorsement,
    signature: unpadded(cryptoSign(
      null,
      Buffer.from(canonicalize(unsignedEndorsement), "utf8"),
      signingKey.privateKey,
    )),
  };
  const submittedEndorsement = await signedPost({
    path: "/endorsements",
    document: endorsement,
    keyid,
    privateKey: signingKey.privateKey,
    nonce: "endorsement-valid",
  });
  assertMediaType(submittedEndorsement, "application/htmltrust-endorsement+json", "endorsement submission");
  await signedPost({
    path: "/endorsements",
    document: endorsement,
    keyid,
    privateKey: signingKey.privateKey,
    nonce: "endorsement-idempotent-repeat",
  });
  const endorsements = await requestJson(
    `${target}/content/${encodeURIComponent(contentHash)}/endorsements`,
  );
  assertMediaType(endorsements, "application/htmltrust-endorsement+json", "endorsement listing");
  if (!Array.isArray(endorsements.body) || endorsements.body.length !== 1) {
    fail("root content endorsement listing did not return the stored document", endorsements.body);
  }

  console.log("HTMLTrust v1 directory smoke: canonical operations and signature profile checks passed");
};

main().catch((error) => {
  console.error(error.stack || error.message);
  process.exit(1);
});
