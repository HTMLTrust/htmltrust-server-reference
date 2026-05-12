# HTMLTrust Trust-Directory Conformance Suite

An implementation-agnostic conformance suite for the HTMLTrust trust-directory
HTTP API. Drop any server that claims to implement [`../openapi.yaml`](../openapi.yaml)
behind a URL, point this runner at it, and learn whether it conforms.

The suite is small on purpose. It validates:

1. **Status codes** for each documented success and error path.
2. **Response envelopes** against the JSON schemas embedded in `openapi.yaml`
   (loaded at runtime — there is no parallel copy of the spec).
3. **End-to-end flows** that span multiple endpoints (e.g. create an author,
   sign content, look up the signature in the directory).

Scenarios are plain YAML files in [`fixtures/`](fixtures/). The runner is a
single ES module ([`runner/run.mjs`](runner/run.mjs)) with one dependency
(`yaml`).

## Quick start (Node reference)

From the repo root:

```sh
npm install            # one-time; installs server + dev dependencies
npm run conformance    # full lifecycle: start mongo, start server, run suite
```

`npm run conformance` invokes
[`runner/with-reference-server.mjs`](runner/with-reference-server.mjs), which:

1. boots a disposable, in-process MongoDB via `mongodb-memory-server`,
2. starts the Node reference server on port 3000 pointed at that mongo,
3. runs every fixture under `fixtures/` against the server (with
   `--accept-mongo-ids` to tolerate known reference deviations),
4. tears mongo and the server down on exit.

It exits non-zero if any fixture fails. Requirements: Node 18+, npm.
No Docker required.

An alternative Docker-based orchestrator is wired up at
`npm run conformance:docker` (requires Docker). See
[`run-conformance.sh`](run-conformance.sh).

## Run against an arbitrary server

```sh
cd conformance/runner
npm install               # one-time
node run.mjs \
  --target-url   http://your-server.example \
  --base-path    /v1 \
  --general-api-key YOUR_GENERAL_KEY \
  --admin-api-key   YOUR_ADMIN_KEY
```

All flags:

| Flag | Default | Description |
|---|---|---|
| `--target-url URL` | `http://localhost:3000` | Base URL of the server |
| `--base-path PATH` | `/api` | Prefix prepended to spec paths. Use `/v1` for spec-conformant servers, `/api` for the Node reference, or `""` for none. |
| `--general-api-key KEY` | env `GENERAL_API_KEY` | Value for `X-API-KEY` |
| `--admin-api-key KEY` | env `ADMIN_API_KEY` | Value for `X-ADMIN-API-KEY` |
| `--fixtures-dir DIR` | `../fixtures` | Where YAML fixtures live |
| `--openapi FILE` | `../../openapi.yaml` | Spec used for schema validation |
| `--accept-mongo-ids` | off | Treat MongoDB-style `_id` as `id` when validating. Enable for the Node reference; leave off for spec-conformant servers. |
| `--only NAME` | (all) | Substring match against fixture filenames; runs only matching ones |
| `--verbose, -v` | off | Print each request/response and captured variables |

Exit codes: `0` on full pass, `1` if any scenario fails, `2` for setup errors.

## Adding fixtures

A fixture is a YAML document with this shape:

```yaml
name: Human-friendly name
description: |
  What this scenario verifies and why.
steps:
  - name: Step description
    request:
      method: POST           # default GET
      path: /authors         # appended to --target-url + --base-path
      headers:
        X-API-KEY: $generalApiKey
      body:
        name: "Example $run_nonce"
        keyType: HUMAN
    expect:
      status: 201            # or a list: [200, 201]
      schema: Author         # named schema from openapi.yaml components, or an inline JSON-Schema
      body:                  # partial match by default; set bodyMatch: exact for full equality
        keyType: HUMAN
      bodyMatch: partial
    capture:
      authorId: $.author.id
      authorApiKey: $.authorApiKey
```

### Variables

Variables are referenced as `$name` or `${name}`. Available automatically:

| Variable | Source |
|---|---|
| `$generalApiKey` | `--general-api-key` flag |
| `$adminApiKey` | `--admin-api-key` flag |
| `$run_nonce` | Auto-generated per scenario run — use to make names unique across reruns |

Fixtures can declare additional defaults under a top-level `vars:` key. Steps
capture new variables via the `capture:` mapping (right-hand sides are a tiny
JSONPath subset — `$`, `$.foo.bar`, `$.list[0]`).

### Body matching placeholders

When you want to assert a field is *present and shaped right* without pinning
an exact value:

| Placeholder | Matches |
|---|---|
| `$any` | Any value (presence only) |
| `$nonempty-string` | A non-empty string |
| `$uuid` | A UUID (or, in `--accept-mongo-ids` mode, a 24-hex ObjectId) |
| `$boolean` | A boolean |
| `$integer` | An integer |
| `$number` | Any number |

### Idempotence

Fixtures are run sequentially and MUST be safe to rerun against a populated
database. The standard pattern is:

1. Create your own author / resource with a name suffixed by `$run_nonce`.
2. Operate on that resource.
3. Don't depend on global state created by other fixtures.

The convenience script starts a fresh Mongo container per run, but external
targets won't necessarily be reset between runs — so write fixtures as if the
database is shared and long-lived.

## Schemas

Schemas live in [`../openapi.yaml`](../openapi.yaml) and are loaded at runtime.
The runner implements a minimal JSON-Schema validator covering the subset of
features used in the spec (type, properties, required, items, enum, format
[uuid/date-time/uri], min/max, allOf, $ref).

If you need a richer validator, swap in `ajv` — `validate()` in
[`runner/run.mjs`](runner/run.mjs) is the only spot to change.

## Why a custom runner instead of Postman / Newman / Schemathesis?

* **Zero install footprint.** One dependency (`yaml`). No Java, no Python, no
  global tooling.
* **First-class multi-step flows.** Most spec testers struggle with
  "create-then-use" patterns. Fixtures here capture values across steps.
* **Implementation-agnostic.** No assumptions about backing store, language,
  framework, or even base path.
* **Spec is the single source of truth.** `openapi.yaml` powers both
  documentation and validation. No drift.

## Known deviations of the Node reference

For transparency — these were observed while building the suite. They are
**not** fixed in this task (out of scope), but the suite is configured to
work around them when run against the Node reference.

1. **`id` fields are 24-char MongoDB ObjectIds, not RFC-4122 UUIDs.**
   `openapi.yaml` specifies `format: uuid` for every id field. The Node
   reference simply emits the underlying Mongoose `_id`. The
   `--accept-mongo-ids` flag relaxes UUID checks to also accept ObjectIds.
2. **Mongoose `_id` is exposed alongside the spec's `id` in many responses.**
   `openapi.yaml` doesn't forbid extra properties (no `additionalProperties:
   false`), so this is technically tolerable; but it leaks implementation
   detail and a strict OpenAPI validator could complain. The same flag
   permits `_id` as a synonym for `id`.
3. **API is mounted under `/api/…` instead of `/v1/…`** as the spec's
   `servers` block implies. `--base-path /api` accommodates this; other
   implementations should use `/v1` or `""` as appropriate.
4. **`/votes` endpoints are implemented but not documented in
   `openapi.yaml`.** Fixtures 05, 06, and 09 exercise them anyway since the
   spec text references endorsement/trust voting. A future spec revision
   is expected to formalize them.

Running the suite in **strict** mode against the reference (drop
`--accept-mongo-ids`, use `--base-path ""`, and target a spec-conformant
server) will surface deviations 1 and 2 immediately; that is the intended
behaviour for verifying other implementations.
