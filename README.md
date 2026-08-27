# HTMLTrust Server Reference (Node.js)

Reference implementation of the HTMLTrust trust directory API — a server that manages author identities, cryptographic key pairs, content signing/verification, and a federated trust directory with reputation tracking.

This is a companion to the [HTMLTrust specification](https://github.com/HTMLTrust/htmltrust-spec).

## Personality: the "permissive community directory"

The HTMLTrust protocol is federated, meaning multiple trust directories MAY coexist with different curatorial philosophies. This Node.js implementation is the baseline reference: full-featured, permissive, and neutral -- suitable for general-purpose deployment and as a canonical implementation of every endpoint in the OpenAPI spec.

The sibling reference implementations demonstrate alternative curatorial philosophies using the same protocol:

- **[`htmltrust-server-reference-python`](../htmltrust-server-reference-python/)** -- curated journalism directory. Admin-approval queue, Article/News scope, punitive reputation formula. Simulates EFF/ProPublica/Poynter-style deployments.
- **[`htmltrust-server-reference-rust`](../htmltrust-server-reference-rust/)** -- rapid-flag public-safety directory. Time-decayed reputation, whitelisted-researcher fatal flagging, PostgreSQL backend. Simulates Internet Archive / security research collective deployments.

All three conform to the same OpenAPI spec. Clients don't need per-directory logic -- they simply subscribe to one or more directories and weight the returned scores according to their own trust policy.

## What It Does

This server implements the **Trust Directory** component of the HTMLTrust system:

- **Author Management** — Create and manage author profiles with cryptographic key pairs
- **Content Signing** — Sign content hashes with author private keys, producing verifiable signatures
- **Content Verification** — Verify that content signatures are authentic and untampered
- **Trust Directory** — Search for public keys, track content occurrences across domains, and manage reputation
- **Voting & Reputation** — Community-driven trust/distrust system for authors and content
- **Claims** — Extensible metadata system for content categorization (authorship type, license, AI involvement, etc.)

## Tech Stack

- **Node.js** + **Express 5**
- **MongoDB** via **Mongoose**
- **Node.js `crypto`** for key generation, signing, and verification (RSA, ECDSA, Ed25519)

## Quick Start

### Prerequisites

- Node.js 18+
- MongoDB (local or remote)

### Setup

```sh
git clone https://github.com/HTMLTrust/htmltrust-server-reference.git
cd htmltrust-server-reference
cp .env.example .env    # Edit with your values
npm install
npm run dev             # Starts with nodemon (auto-reload)
```

The server starts at `http://localhost:3000`. A demo web UI is available at the root URL.

### Tests

```sh
npm test          # unit tests: JCS, claims canonicalization, RFC 9421 verification
npm run conformance   # full API conformance suite against a disposable MongoDB
```

`npm test` needs no database. `npm run conformance` boots `mongodb-memory-server` and the reference server itself; set `SERVER_PORT` / `MONGO_PORT` if 3000 or 37017 are taken.

### Environment Variables

See `.env.example` for all options. At minimum you need:

| Variable | Description |
|---|---|
| `MONGO_URI` | MongoDB connection string |
| `AUTHOR_API_KEY_PEPPER` | Pepper for author API key hashing. Required when `NODE_ENV=production`; the server refuses to start without it |
| `GENERAL_API_KEY` | Supplementary demo key for submission endpoints |
| `ADMIN_API_KEY` | Admin key for directory-operator operations (defining claim types, endorsement takedown) |

## API Overview

Full API documentation is in [`openapi.yaml`](openapi.yaml). Key endpoint groups:

| Path | Description | Auth |
|---|---|---|
| `GET /api/.well-known/htmltrust` | Discover directory capabilities | Public |
| `GET /api/content/:hash` | Get draft content record by percent-encoded hash | Public |
| `POST /api/content` | Submit a signed content occurrence | HTTP Message Signature |
| `GET /api/content/:hash/endorsements` | List structured endorsements for a content hash | Public |
| `GET /api/keys/:id` | Get draft key document | Public |
| `GET /api/signers/:id/reputation` | Get draft signer reputation | Public |
| `POST /api/authors` | Create author + key pair | General API key |
| `GET /api/authors/:id/public-key` | Get author's public key | Public |
| `POST /api/content/sign` | Compatibility helper: sign contentHash + claimsHash | Author API key |
| `POST /api/content/verify` | Verify a signature (deprecated, see below) | Public |
| `GET /api/directory/keys` | Search public keys | Public |
| `GET /api/directory/content` | Search signed content | Public |
| `GET /api/endorsements?content-hash=...` | List endorsements for a content hash | Public |
| `POST /api/endorsements` | Submit a signed endorsement | HTTP Message Signature |
| `DELETE /api/endorsements/:id` | Delete an endorsement | Endorser's own key, or admin key |
| `POST /api/votes` | Vote trust/distrust | HTTP Message Signature |

### Deprecated endpoints

`POST /api/content/verify` is deprecated. Per [HTMLTrust spec §3.1](https://htmltrust.dev/spec#section-3-1), cryptographic verification is a local operation: clients MUST verify signatures themselves (e.g. via `SubtleCrypto`) using public keys resolved through the directory's key endpoints. A remote yes/no answer from the directory is by definition not a cryptographic guarantee since the directory is not part of the trust root. The endpoint remains as a low-trust convenience for legacy clients, returns the `Deprecation: true` header (RFC 9745), and will be removed in a future major version. The directory's role is to serve public keys, endorsements, and reputation data — not to act as an oracle for signature validity.

### Draft wire-format notes

Hashes, signatures, and key bytes use canonical unpadded standard Base64, not base64url. JSON fields named `domain` carry the serialized Web origin (`scheme://host[:port]`), not a bare hostname. Content signatures bind `contentHash:claimsHash:domain:signedAt`, where `claimsHash` is the SHA-256 of the draft §4.6 canonical claims serialization over all direct child `meta` claims in the signed section.

Endorsement signatures cover the RFC 8785 JCS serialization of the endorsement document with the `signature` member omitted (draft §10.2). The directory verifies that signature against the endorser's resolved key before storing anything, and serves the stored document back byte-for-byte: it injects no `_id`, `createdAt`, or `contentHash` alias, because §10.1 requires unrecognised members to be included in the signed payload, so any injected member would break verification for the next reader. The identifier of a newly stored endorsement is returned in the `Location` header of the 201 response. `contentHash` appears only on documents stored by earlier versions of this server.

Endorsements are append-only. Resubmitting an identical document is idempotent (200 instead of 201); a different document from the same endorser for the same content hash — a revocation, for instance — is stored alongside the original, because §10.3 requires a directory holding both to serve both.

### Authentication

Draft §9.8 requires POST endpoints to authenticate with an [RFC 9421](https://www.rfc-editor.org/rfc/rfc9421) HTTP Message Signature made with a key the directory can resolve per §8. The signature MUST cover the request target, `host`, `date`, and — for requests with a body — `content-digest`:

```
Signature-Input: sig1=("@method" "@target-uri" "host" "date" "content-digest");\
  created=1770000000;keyid="https://directory.example/api/keys/k-abc123"
Signature: sig1=:MEUCIQD...:
```

The authenticated identity is the resolved key, which is what lets the directory bind a submission, a vote, or an endorsement deletion to a specific signer.

The static API keys below remain as a supplementary demo and operator scheme. A shared secret says nothing about *who* sent a request, so it cannot carry submitter identity; requests authenticated this way vote as a single collapsed identity and cannot delete another party's endorsement. They are refused when `NODE_ENV=production` unless `HTMLTRUST_ALLOW_API_KEY_AUTH=1` is set.

| Header | Purpose |
|---|---|
| `X-API-KEY` | Demo submission key (creating authors, voting, reporting) |
| `X-AUTHOR-API-KEY` | Author-specific operations (directory-side signing, updating own profile) |
| `X-ADMIN-API-KEY` | Directory-operator operations (managing claim types, endorsement takedown) |

Author API keys are stored as an HMAC-SHA-256 under `AUTHOR_API_KEY_PEPPER` and are shown exactly once, at author creation. Deployments upgrading from a version that stored them in plaintext need the one-time migration described in `src/utils/apiKeys.js`; databases created before endorsements became append-only also need the two unique indexes dropped, as described in `src/models/Endorsement.js`.

### Key custody

`POST /api/authors` accepts an optional `publicKey` (SPKI PEM). Supply it to register a key you already hold: the directory then stores no private key for that author, and content is signed locally and submitted through `POST /api/content`. Omit it and the directory generates and holds the key pair, acting as the convenience registry of draft §9.6.

Resolving `did:` and `https:` keyids means dereferencing URLs chosen by whoever submits a record, which is a server-side request forgery primitive. It is therefore off by default; only keys held by this directory resolve. Set `HTMLTRUST_REMOTE_KEY_RESOLUTION=1` to enable it.

## Project Structure

```
src/
├── server.js              # Express app entry point
├── config/
│   └── db.js              # MongoDB connection
├── controllers/           # Route handlers
│   ├── authorController.js
│   ├── claimController.js
│   ├── contentController.js
│   ├── directoryController.js
│   ├── endorsementController.js
│   └── voteController.js
├── middleware/
│   └── auth.js            # API key authentication
├── models/                # Mongoose schemas
│   ├── Author.js
│   ├── Claim.js
│   ├── ContentOccurrence.js
│   ├── ContentSignature.js
│   ├── Endorsement.js
│   ├── Key.js
│   └── Vote.js
├── public/                # Demo web UI
│   ├── index.html
│   └── js/main.js
├── routes/                # Express route definitions
│   ├── authors.js
│   ├── claims.js
│   ├── content.js
│   ├── directory.js
│   ├── endorsements.js
│   └── votes.js
└── utils/
    └── crypto.js          # Key generation, signing, verification
```

## Companion Repositories

| Repository | Description |
|---|---|
| [htmltrust-spec](https://github.com/HTMLTrust/htmltrust-spec) | The HTMLTrust specification and paper |
| [htmltrust-browser-reference](https://github.com/HTMLTrust/htmltrust-browser-reference) | Reference browser extension for signature validation |
| [htmltrust-cms-reference](https://github.com/HTMLTrust/htmltrust-cms-reference) | Reference CMS plugin (WordPress) |
| [htmltrust-website](https://github.com/HTMLTrust/htmltrust-website) | Project website |

## License


This project is licensed under the [PolyForm Noncommercial License 1.0.0](https://polyformproject.org/licenses/noncommercial/1.0.0). You may use, modify, and share the software for any noncommercial purpose with attribution. Commercial use requires a separate agreement with the licensor.

## Origin & Contributions

HTMLTrust is an idea I (Jason Grey) have been chewing on since 2024. I'm not an academic — I'm an engineer with a day job and a family — so the spec, the reference implementations, and most of this prose have been written with significant help from AI tools acting as research assistant, technical writer, and pair programmer. I wrote the original architectural sketches and reviewed every line; the assistants filled in the gaps and saved me from re-typing the same explanation for the hundredth time.

**Contributions are welcome — human or AI-assisted, doesn't matter to me.** What matters is whether the code, the spec text, or the conformance vectors move the project forward. Open a PR.

What this project is **not** a forum for:

- Debates about whether AI should be used to write code or specifications.
- Opinions on who is or isn't trustworthy on the web.
- Politics, religion, professional practice, or personal philosophy.

HTMLTrust is a mechanism — a way for *anyone* to sign content they publish and for *anyone* to decide whom they trust, on their own terms. The project takes no position on what the right answers are; it just provides the tools. If you want to debate the answers, there are entire continents of the internet better suited to it.

If this work is useful to you and you'd like to support it, see [GitHub Sponsors](https://github.com/sponsors/jt55401) or the other channels in [`.github/FUNDING.yml`](.github/FUNDING.yml).
