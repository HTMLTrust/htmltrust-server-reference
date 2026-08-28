# HTMLTrust Server Reference

This repository contains the runnable Node.js reference server for the HTMLTrust trust directory API. It stores author profiles and public keys, accepts signed content and endorsements, and exposes directory search and reputation data.

The wire contract is documented in [`openapi.yaml`](openapi.yaml). The server is the implementation used by the local development workflow and the end-to-end simulation.

## Quick start

### Requirements

For a local Node run, install:

- Node.js 22 or newer
- MongoDB 7 or a compatible MongoDB deployment

Docker users can run the complete test suite without installing Node.js or MongoDB. See [Test in Docker](#test-in-docker).

### Checkout, install, and run

```sh
git clone https://github.com/HTMLTrust/htmltrust-server-reference.git
cd htmltrust-server-reference
npm ci
cp .env.example .env
npm run dev
```

Set `MONGO_URI` in `.env` to the database used by the server. The default development URI is `mongodb://localhost:27017/content-signing`, and the server listens on port `3000`. Open `http://localhost:3000/` for the demo page.

`npm run dev` uses nodemon. Use `npm start` for a regular Node process.

### Run tests

Unit tests use Node's built-in test runner and require no database:

```sh
npm test
npm run openapi:lint
```

Install the conformance runner once, then run the reference server against a disposable in-process MongoDB:

```sh
npm --prefix conformance/runner ci
npm run conformance
```

The conformance command runs every fixture and the canonical v1 smoke checks. Set `SERVER_PORT` or `MONGO_PORT` when the defaults are occupied. The first run can download a MongoDB binary for `mongodb-memory-server`.

## Test in Docker

The repository script runs unit and conformance tests inside a disposable Node 22 container. It mounts the checkout read-only, copies sources into the container, and installs dependencies there. Test output and generated runtime files leave no files in the checkout. Checkout-scoped Docker volumes cache npm packages and the MongoDB test binary.

```sh
./scripts/test-in-docker.sh
```

This is the lowest-dependency test path: it requires Docker and a shell. Set `HTMLTRUST_TEST_IMAGE` to use another compatible Node image. The older `npm run conformance:docker` command remains available for developers who want to run the conformance runner with a host Node process and a Docker MongoDB container.

## Deployment

1. Provision MongoDB 7, create a database for this service, and set `MONGO_URI` with credentials appropriate for the deployment.
2. Install production dependencies from the lockfile:

   ```sh
   npm ci --omit=dev
   ```

3. Set `NODE_ENV=production`, `AUTHOR_API_KEY_PEPPER`, and `DIRECTORY_BASE_URL`. Use a random, long-lived pepper and keep it outside the repository. `DIRECTORY_BASE_URL` must be the public origin clients use to resolve directory key URLs.
4. Set `GENERAL_API_KEY` and `ADMIN_API_KEY` when compatibility or operator routes need them. Static general and author API-key authentication is disabled in production unless `HTMLTRUST_ALLOW_API_KEY_AUTH=1` is set.
5. Start the service with `npm start` behind a TLS-terminating reverse proxy. Set `TRUST_PROXY` to the number of trusted proxy hops when the proxy forwards client addresses.

Before upgrading a database created by an earlier server version, run the explicit index migration with the same connection string used by the service:

```sh
MONGO_URI="mongodb://user:password@db.example/htmltrust" npm run migrate:v1
```

The migration replaces the legacy content identity and endorsement indexes. Run it during a maintenance window and verify backups before changing production data.

See [.env.example](.env.example) for every supported setting. Remote `did:` and HTTPS key resolution is disabled by default because dereferencing submitter-provided URLs creates an outbound-request risk. Enable `HTMLTRUST_REMOTE_KEY_RESOLUTION=1` only after reviewing the network policy for the deployment.

## API

The server exposes two HTTP surfaces. The root routes are the canonical HTMLTrust v1 directory surface. The `/api` routes are compatibility routes used by the demo UI and existing integrations.

### Canonical v1 routes

| Method and path | Purpose | Authentication |
|---|---|---|
| `GET /.well-known/htmltrust` | Discover directory version, capabilities, algorithms, and profiles | Public |
| `GET /keys/:id` | Retrieve a directory key document | Public |
| `GET /signers/:id/reputation` | Retrieve signer reputation | Public |
| `POST /content` | Submit and re-verify a signed content record | RFC 9421 HTTP Message Signature |
| `GET /content/:hash` | Retrieve a content record by percent-encoded hash | Public |
| `GET /content/:hash/endorsements` | List endorsements for a content hash | Public |
| `GET /endorsements?content-hash=...` | List endorsements for a content hash | Public |
| `POST /endorsements` | Store a signed endorsement | RFC 9421 HTTP Message Signature |
| `DELETE /endorsements/:id` | Delete an endorsement with the endorser key or directory admin key | Endorser signature or admin key |

Canonical writes require a resolvable key in an RFC 9421 signature. The covered components include `@method`, `@target-uri`, `host`, `date`, and `content-digest` for requests with a body. The `keyid` identifies the key that signed the request.

Canonical reads return an HTMLTrust media type by default and accept `application/json`. Responses include `Vary: Accept`; public reads include `Cache-Control` and `ETag`. A matching `If-None-Match` request receives `304 Not Modified`. Canonical JSON submissions accept `application/json` and `application/*+json`; another request media type receives `415`.

### Compatibility routes

The following routes retain the original `/api` prefix and response shapes:

| Route group | Operations |
|---|---|
| `/api/authors` | Create and list authors; read, update, or delete an author; read its public key |
| `/api/content` | Sign, verify, submit, and retrieve content; register occurrences; list content endorsements |
| `/api/claims` | Create, list, read, update, and delete claim types |
| `/api/directory` | Search keys and content; read key reputation and occurrences; report keys or content |
| `/api/endorsements` | List, submit, and delete endorsements |
| `/api/votes` | Submit votes; list votes; read vote statistics; delete a vote |
| `/api/keys` and `/api/signers` | Read the compatibility key and signer-reputation documents |
| `/api/.well-known/htmltrust` | Compatibility alias for the discovery document |

The compatibility routes use the API-key headers described below for their original protected operations. Content and endorsement submission also accept the RFC 9421 flow, while canonical root submissions require that flow. The OpenAPI file defines the long-term v1 resource shapes and media types; this implementation currently keeps author, claim-management, directory-search, reporting, and voting operations under `/api`.

### Deprecated route

`POST /api/content/verify` is deprecated and returns `Deprecation: true` as specified by RFC 9745. Signature verification belongs in the client, using a public key retrieved from the directory and a local cryptographic API such as `SubtleCrypto`. The route remains for legacy clients and will be removed in a future major version. There is no canonical root `/content/verify` route.

### Authentication headers

Use RFC 9421 signatures for canonical writes. The compatibility surface supports these headers when its API-key authentication is enabled:

| Header | Use |
|---|---|
| `X-API-KEY` | General compatibility operations, including author creation, occurrence registration, reporting, and demo submissions |
| `X-AUTHOR-API-KEY` | Author-specific compatibility operations and the compatibility signing helper |
| `X-ADMIN-API-KEY` | Claim-type administration and endorsement takedown |

Author API keys are returned once by `POST /api/authors`. The server stores an HMAC-SHA-256 digest under `AUTHOR_API_KEY_PEPPER`. A deployment that still has plaintext keys must migrate them using the procedure in [`src/utils/apiKeys.js`](src/utils/apiKeys.js), then remove the plaintext field.

### Wire-format details

- Hashes, signatures, and key bytes use unpadded standard Base64.
- `domain` values are serialized web origins such as `https://publisher.example:8443`.
- Content signatures bind `contentHash`, `claimsHash`, `domain`, and `signedAt`. `claimsHash` covers the canonical serialization of direct `meta` claims in the signed section.
- Endorsement signatures cover the RFC 8785 JCS serialization of the endorsement document with `signature` omitted. New endorsements are served as signed, and the 201 response supplies the stored identifier in `Location`.
- Endorsements are append-only. An identical retry on canonical `POST /endorsements` returns `201` with the existing resource in `Location`; the `/api/endorsements` compatibility route returns `200`. A different document from the same endorser and content hash is stored as another record.

### Key custody

`POST /api/authors` accepts an optional SPKI PEM `publicKey`. Supplying one registers a key held by the caller and leaves its private key outside the directory. Omitting it asks the server to generate and hold a key pair for the convenience registry flow. Content signed by a caller-held key is submitted through `POST /content` or the compatibility `POST /api/content` route.

## Project structure

```text
src/
├── server.js                 Express application entry point
├── config/                   MongoDB connection setup
├── controllers/              Request handlers
├── middleware/               Authentication and content negotiation
├── models/                   Mongoose schemas
├── public/                   Demo web UI
├── routes/                   Compatibility route definitions
└── utils/                    Cryptography and protocol helpers
conformance/
├── fixtures/                 YAML API scenarios
└── runner/                   Implementation-agnostic conformance runner
scripts/test-in-docker.sh     Docker-only unit and conformance entrypoint
openapi.yaml                  API contract and response schemas
```

## Related repositories

- [HTMLTrust specification](https://github.com/HTMLTrust/htmltrust-spec)
- [Browser reference](https://github.com/HTMLTrust/htmltrust-browser-reference)
- [CMS reference](https://github.com/HTMLTrust/htmltrust-cms-reference)
- [Project website](https://github.com/HTMLTrust/htmltrust-website)

## License and contributions

This project is licensed under the [PolyForm Noncommercial License 1.0.0](https://polyformproject.org/licenses/noncommercial/). Commercial use requires a separate agreement with the licensor.

Issues and pull requests are welcome. Contributions may include code, specification text, documentation, or conformance fixtures. Please keep changes focused on improving the protocol and its implementations.
