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

### Environment Variables

See `.env.example` for all options. At minimum you need:

| Variable | Description |
|---|---|
| `MONGO_URI` | MongoDB connection string |
| `GENERAL_API_KEY` | API key for general authenticated operations |
| `ADMIN_API_KEY` | API key for admin operations (e.g., defining claim types) |

## API Overview

Full API documentation is in [`openapi.yaml`](openapi.yaml). Key endpoint groups:

| Path | Description | Auth |
|---|---|---|
| `POST /api/authors` | Create author + key pair | General API key |
| `GET /api/authors/:id/public-key` | Get author's public key | Public |
| `POST /api/content/sign` | Sign a content hash | Author API key |
| `POST /api/content/verify` | Verify a signature (deprecated, see below) | Public |
| `GET /api/directory/keys` | Search public keys | Public |
| `GET /api/directory/content` | Search signed content | Public |
| `GET /api/endorsements?content-hash=...` | List endorsements for a content hash | Public |
| `POST /api/endorsements` | Submit a signed endorsement | General API key |
| `DELETE /api/endorsements/:id` | Delete an endorsement | General API key |
| `POST /api/votes` | Vote trust/distrust | General API key |

### Deprecated endpoints

`POST /api/content/verify` is deprecated. Per [HTMLTrust spec §3.1](https://htmltrust.dev/spec#section-3-1), cryptographic verification is a local operation: clients MUST verify signatures themselves (e.g. via `SubtleCrypto`) using public keys resolved through the directory's key endpoints. A remote yes/no answer from the directory is by definition not a cryptographic guarantee since the directory is not part of the trust root. The endpoint remains as a low-trust convenience for legacy clients, returns the `Deprecation: true` header (RFC 9745), and will be removed in a future major version. The directory's role is to serve public keys, endorsements, and reputation data — not to act as an oracle for signature validity.

### Authentication

Three tiers of API key auth via headers:

| Header | Purpose |
|---|---|
| `X-API-KEY` | General operations (creating authors, voting, reporting) |
| `X-AUTHOR-API-KEY` | Author-specific operations (signing, updating own profile) |
| `X-ADMIN-API-KEY` | Admin operations (managing claim types) |

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

MIT