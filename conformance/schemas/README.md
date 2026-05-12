# Schemas

This directory is intentionally empty.

The conformance runner loads JSON-Schema definitions directly from
`../../openapi.yaml` at runtime (see `runner/run.mjs`, `loadOpenAPI` and
`getNamedSchema`). Treating `openapi.yaml` as the single source of truth
means a spec change automatically flows through the conformance suite —
no regeneration step.

If you need to validate against a vendored copy of the spec (e.g. when
the target server pins a specific spec revision), pass the path to the
runner with `--openapi /path/to/openapi.yaml`.
