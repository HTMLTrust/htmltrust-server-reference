#!/usr/bin/env node
/**
 * HTMLTrust Trust-Directory Conformance Runner
 *
 * Implementation-agnostic conformance suite. Loads YAML fixtures under
 * conformance/fixtures/, executes each scenario's steps against a target
 * server, and validates responses against schemas derived from openapi.yaml.
 *
 * Usage:
 *   node run.mjs --target-url http://localhost:3000 \
 *                --base-path /api \
 *                --general-api-key KEY \
 *                --admin-api-key KEY \
 *                [--fixtures-dir ../fixtures] \
 *                [--openapi ../../openapi.yaml] \
 *                [--accept-mongo-ids] \
 *                [--only 02-author-crud] \
 *                [--verbose]
 *
 * Exit codes:
 *   0 — all scenarios passed
 *   1 — one or more scenarios failed
 *   2 — bad CLI usage / fatal setup error
 */

import { readFile, readdir } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, resolve, join, basename } from "node:path";
import YAML from "yaml";

const SELF_DIR = dirname(fileURLToPath(import.meta.url));

// ---------- CLI parsing ----------------------------------------------------

function parseArgs(argv) {
  const args = {
    targetUrl: "http://localhost:3000",
    basePath: "/api",
    generalApiKey: process.env.GENERAL_API_KEY || "change_me_general_key",
    adminApiKey: process.env.ADMIN_API_KEY || "change_me_admin_key",
    fixturesDir: resolve(SELF_DIR, "..", "fixtures"),
    openapi: resolve(SELF_DIR, "..", "..", "openapi.yaml"),
    acceptMongoIds: false,
    only: null,
    verbose: false,
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const next = () => argv[++i];
    switch (a) {
      case "--target-url": args.targetUrl = next(); break;
      case "--base-path": args.basePath = next(); break;
      case "--general-api-key": args.generalApiKey = next(); break;
      case "--admin-api-key": args.adminApiKey = next(); break;
      case "--fixtures-dir": args.fixturesDir = resolve(next()); break;
      case "--openapi": args.openapi = resolve(next()); break;
      case "--accept-mongo-ids": args.acceptMongoIds = true; break;
      case "--only": args.only = next(); break;
      case "--verbose": case "-v": args.verbose = true; break;
      case "--help": case "-h":
        printHelp();
        process.exit(0);
      default:
        console.error(`Unknown argument: ${a}`);
        printHelp();
        process.exit(2);
    }
  }
  // Normalize: strip trailing slash from target/base path
  args.targetUrl = args.targetUrl.replace(/\/+$/, "");
  args.basePath = args.basePath.replace(/\/+$/, "");
  return args;
}

function printHelp() {
  process.stdout.write(
`HTMLTrust trust-directory conformance runner

Usage: node run.mjs [options]

Options:
  --target-url URL         Base URL of the target server (default: http://localhost:3000)
  --base-path PATH         Path prefix prepended to spec paths (default: /api)
  --general-api-key KEY    Value for X-API-KEY header
  --admin-api-key KEY      Value for X-ADMIN-API-KEY header
  --fixtures-dir DIR       Directory of YAML fixtures (default: ../fixtures)
  --openapi FILE           Path to openapi.yaml (default: ../../openapi.yaml)
  --accept-mongo-ids       Treat MongoDB-style "_id" as if it were "id" when validating
                           (use when testing the Node reference implementation)
  --only NAME              Only run fixtures whose filename matches NAME (substring)
  --verbose, -v            Print request/response details for each step
  --help, -h               Show this help
`);
}

// ---------- OpenAPI loading & schema lookup --------------------------------

async function loadOpenAPI(path) {
  const text = await readFile(path, "utf8");
  return YAML.parse(text);
}

/**
 * Resolve a $ref reference (e.g. "#/components/schemas/Author") against the
 * loaded OpenAPI document. Throws if the ref cannot be resolved.
 */
function resolveRef(doc, ref) {
  if (!ref.startsWith("#/")) {
    throw new Error(`Only internal refs supported, got: ${ref}`);
  }
  const parts = ref.slice(2).split("/");
  let cur = doc;
  for (const p of parts) {
    if (cur == null || !(p in cur)) {
      throw new Error(`Cannot resolve ref ${ref} (failed at "${p}")`);
    }
    cur = cur[p];
  }
  return cur;
}

/**
 * Look up a named schema by name from components.schemas.
 */
function getNamedSchema(doc, name) {
  const schemas = doc.components && doc.components.schemas;
  if (!schemas || !(name in schemas)) {
    throw new Error(`No schema named "${name}" in openapi components`);
  }
  return schemas[name];
}

// ---------- JSON Schema validator ------------------------------------------

/**
 * A small JSON-Schema validator scoped to the subset of features used by
 * openapi.yaml: type, properties, required, items, enum, format (uuid /
 * date-time / uri / float / int), minimum/maximum, additionalProperties,
 * allOf, $ref. Returns an array of error strings; empty if valid.
 *
 * Options:
 *   acceptMongoIds: when true, accepts "_id" as equivalent to "id" in objects
 *                   whose schema requires "id".
 */
function validate(value, schema, doc, opts = {}, path = "$") {
  const errs = [];
  if (schema == null) return errs;

  if (schema.$ref) {
    return validate(value, resolveRef(doc, schema.$ref), doc, opts, path);
  }

  if (Array.isArray(schema.allOf)) {
    for (const sub of schema.allOf) {
      errs.push(...validate(value, sub, doc, opts, path));
    }
    return errs;
  }

  if (schema.oneOf || schema.anyOf) {
    const variants = schema.oneOf || schema.anyOf;
    const subErrs = variants.map((s) => validate(value, s, doc, opts, path));
    const passed = subErrs.filter((e) => e.length === 0).length;
    if (passed === 0) {
      errs.push(`${path}: did not match any of oneOf/anyOf variants`);
    }
    return errs;
  }

  const type = schema.type;
  if (type === "object" || (type == null && schema.properties)) {
    if (value === null || typeof value !== "object" || Array.isArray(value)) {
      errs.push(`${path}: expected object, got ${jsType(value)}`);
      return errs;
    }
    // required
    if (Array.isArray(schema.required)) {
      for (const req of schema.required) {
        const present = req in value ||
          (opts.acceptMongoIds && req === "id" && "_id" in value);
        if (!present) {
          errs.push(`${path}: missing required property "${req}"`);
        }
      }
    }
    // properties
    if (schema.properties) {
      for (const [k, subSchema] of Object.entries(schema.properties)) {
        let propValue;
        let propPresent = false;
        if (k in value) {
          propValue = value[k];
          propPresent = true;
        } else if (opts.acceptMongoIds && k === "id" && "_id" in value) {
          propValue = value._id;
          propPresent = true;
        }
        if (propPresent) {
          errs.push(...validate(propValue, subSchema, doc, opts, `${path}.${k}`));
        }
      }
    }
    return errs;
  }

  if (type === "array") {
    if (!Array.isArray(value)) {
      errs.push(`${path}: expected array, got ${jsType(value)}`);
      return errs;
    }
    if (schema.items) {
      for (let i = 0; i < value.length; i++) {
        errs.push(...validate(value[i], schema.items, doc, opts, `${path}[${i}]`));
      }
    }
    return errs;
  }

  if (type === "string") {
    if (typeof value !== "string") {
      errs.push(`${path}: expected string, got ${jsType(value)}`);
      return errs;
    }
    if (Array.isArray(schema.enum) && !schema.enum.includes(value)) {
      errs.push(`${path}: value "${value}" not in enum ${JSON.stringify(schema.enum)}`);
    }
    if (schema.format === "uuid") {
      // Permissive: any string that *could* be an id (UUID or 24-char hex
      // for MongoDB ObjectId) is accepted when acceptMongoIds is true.
      const uuidRe = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
      const objIdRe = /^[0-9a-f]{24}$/i;
      const ok = uuidRe.test(value) || (opts.acceptMongoIds && objIdRe.test(value));
      if (!ok) {
        errs.push(`${path}: value "${value}" is not a valid UUID`);
      }
    } else if (schema.format === "date-time") {
      if (Number.isNaN(Date.parse(value))) {
        errs.push(`${path}: value "${value}" is not a valid date-time`);
      }
    } else if (schema.format === "uri") {
      try { new URL(value); }
      catch { errs.push(`${path}: value "${value}" is not a valid URI`); }
    }
    return errs;
  }

  if (type === "integer") {
    if (typeof value !== "number" || !Number.isInteger(value)) {
      errs.push(`${path}: expected integer, got ${jsType(value)}`);
    }
    if (typeof schema.minimum === "number" && value < schema.minimum) {
      errs.push(`${path}: value ${value} < minimum ${schema.minimum}`);
    }
    if (typeof schema.maximum === "number" && value > schema.maximum) {
      errs.push(`${path}: value ${value} > maximum ${schema.maximum}`);
    }
    return errs;
  }

  if (type === "number") {
    if (typeof value !== "number") {
      errs.push(`${path}: expected number, got ${jsType(value)}`);
    }
    if (typeof schema.minimum === "number" && value < schema.minimum) {
      errs.push(`${path}: value ${value} < minimum ${schema.minimum}`);
    }
    if (typeof schema.maximum === "number" && value > schema.maximum) {
      errs.push(`${path}: value ${value} > maximum ${schema.maximum}`);
    }
    return errs;
  }

  if (type === "boolean") {
    if (typeof value !== "boolean") {
      errs.push(`${path}: expected boolean, got ${jsType(value)}`);
    }
    return errs;
  }

  // Unknown / no type: accept anything.
  return errs;
}

function jsType(v) {
  if (v === null) return "null";
  if (Array.isArray(v)) return "array";
  return typeof v;
}

// ---------- Body matchers --------------------------------------------------

/**
 * Match an expected body fragment against an actual body. Supports two modes:
 *   partial (default): every key in `expected` must be present in `actual`
 *                       and deep-equal; extra keys in `actual` are allowed.
 *   exact:              actual must deep-equal expected.
 * Special expected values:
 *   "$any"             matches any value (just asserts presence)
 *   "$nonempty-string" matches any non-empty string
 *   "$uuid"            matches any UUID or (with acceptMongoIds) ObjectId
 *   "$boolean"         matches any boolean
 *   "$integer"         matches any integer
 *   "$number"          matches any number
 */
function matchBody(expected, actual, opts = {}, mode = "partial", path = "$") {
  const errs = [];
  if (expected === undefined) return errs;

  if (typeof expected === "string" && expected.startsWith("$")) {
    return matchPlaceholder(expected, actual, opts, path);
  }

  if (expected === null) {
    if (actual !== null) errs.push(`${path}: expected null, got ${jsType(actual)}`);
    return errs;
  }

  if (Array.isArray(expected)) {
    if (!Array.isArray(actual)) {
      errs.push(`${path}: expected array, got ${jsType(actual)}`);
      return errs;
    }
    if (mode === "exact" && expected.length !== actual.length) {
      errs.push(`${path}: expected array length ${expected.length}, got ${actual.length}`);
    }
    for (let i = 0; i < expected.length; i++) {
      errs.push(...matchBody(expected[i], actual[i], opts, mode, `${path}[${i}]`));
    }
    return errs;
  }

  if (typeof expected === "object") {
    if (actual === null || typeof actual !== "object" || Array.isArray(actual)) {
      errs.push(`${path}: expected object, got ${jsType(actual)}`);
      return errs;
    }
    const expectedKeys = Object.keys(expected);
    if (mode === "exact") {
      const actualKeys = Object.keys(actual);
      const extra = actualKeys.filter((k) => !expectedKeys.includes(k));
      if (extra.length > 0) {
        errs.push(`${path}: unexpected keys ${JSON.stringify(extra)}`);
      }
    }
    for (const k of expectedKeys) {
      let actualVal;
      if (k in actual) actualVal = actual[k];
      else if (opts.acceptMongoIds && k === "id" && "_id" in actual) actualVal = actual._id;
      else {
        errs.push(`${path}: missing key "${k}"`);
        continue;
      }
      errs.push(...matchBody(expected[k], actualVal, opts, mode, `${path}.${k}`));
    }
    return errs;
  }

  // Primitive
  if (expected !== actual) {
    errs.push(`${path}: expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`);
  }
  return errs;
}

function matchPlaceholder(placeholder, actual, opts, path) {
  switch (placeholder) {
    case "$any":
      return [];
    case "$nonempty-string":
      return typeof actual === "string" && actual.length > 0
        ? []
        : [`${path}: expected non-empty string, got ${JSON.stringify(actual)}`];
    case "$uuid": {
      if (typeof actual !== "string") {
        return [`${path}: expected UUID string, got ${jsType(actual)}`];
      }
      const uuidRe = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
      const objIdRe = /^[0-9a-f]{24}$/i;
      const ok = uuidRe.test(actual) || (opts.acceptMongoIds && objIdRe.test(actual));
      return ok ? [] : [`${path}: not a UUID: ${actual}`];
    }
    case "$boolean":
      return typeof actual === "boolean" ? [] : [`${path}: expected boolean, got ${jsType(actual)}`];
    case "$integer":
      return Number.isInteger(actual) ? [] : [`${path}: expected integer, got ${jsType(actual)}`];
    case "$number":
      return typeof actual === "number" ? [] : [`${path}: expected number, got ${jsType(actual)}`];
    default:
      return [`${path}: unknown placeholder "${placeholder}"`];
  }
}

// ---------- Variable interpolation -----------------------------------------

/**
 * Recursively walk an object/string and replace ${var} or $var references
 * with values from `vars`. Standalone strings of the form "$varName" or
 * "${varName}" are replaced by the raw value (allowing non-string values).
 * Embedded references inside larger strings are stringified.
 */
function interpolate(value, vars) {
  if (typeof value === "string") {
    // Whole-string substitution preserves type.
    const wholeMatch = value.match(/^\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?$/);
    if (wholeMatch) {
      const k = wholeMatch[1];
      if (k in vars) return vars[k];
      return value;
    }
    // Embedded substitution.
    return value.replace(/\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?/g, (m, k) => {
      return k in vars ? String(vars[k]) : m;
    });
  }
  if (Array.isArray(value)) {
    return value.map((v) => interpolate(v, vars));
  }
  if (value && typeof value === "object") {
    const out = {};
    for (const [k, v] of Object.entries(value)) out[k] = interpolate(v, vars);
    return out;
  }
  return value;
}

/**
 * Extract a value from an object via a tiny JSONPath subset:
 *   $            — the whole object
 *   $.foo.bar    — nested property access
 *   $.list[0]    — array indexing
 *   $._id        — leading-underscore properties
 */
function jsonPath(obj, expr) {
  if (expr === "$") return obj;
  if (!expr.startsWith("$")) {
    throw new Error(`Invalid path "${expr}" (must start with $)`);
  }
  let cur = obj;
  const rest = expr.slice(1);
  const tokens = rest.match(/(?:\.[A-Za-z_][A-Za-z0-9_]*)|(?:\[\d+\])/g) || [];
  for (const tok of tokens) {
    if (cur == null) return undefined;
    if (tok.startsWith(".")) cur = cur[tok.slice(1)];
    else if (tok.startsWith("[")) cur = cur[parseInt(tok.slice(1, -1), 10)];
  }
  return cur;
}

// ---------- Fixture loading ------------------------------------------------

async function loadFixtures(dir, only) {
  const entries = await readdir(dir);
  const yamlFiles = entries
    .filter((f) => f.endsWith(".yaml") || f.endsWith(".yml"))
    .sort();
  const fixtures = [];
  for (const f of yamlFiles) {
    const name = f.replace(/\.ya?ml$/, "");
    if (only && !name.includes(only)) continue;
    const text = await readFile(join(dir, f), "utf8");
    const parsed = YAML.parse(text);
    fixtures.push({ filename: f, name, doc: parsed });
  }
  return fixtures;
}

// ---------- HTTP helper ----------------------------------------------------

async function performRequest({ targetUrl, basePath }, step, vars) {
  const req = interpolate(step.request, vars);
  const method = (req.method || "GET").toUpperCase();
  const path = req.path.startsWith("/") ? req.path : `/${req.path}`;
  const url = `${targetUrl}${basePath}${path}`;

  const headers = { ...(req.headers || {}) };
  let body;
  if (req.body !== undefined) {
    if (typeof req.body === "string") {
      body = req.body;
    } else {
      body = JSON.stringify(req.body);
      if (!Object.keys(headers).some((h) => h.toLowerCase() === "content-type")) {
        headers["Content-Type"] = "application/json";
      }
    }
  }

  const res = await fetch(url, { method, headers, body });
  const text = await res.text();
  let parsed;
  if (text.length === 0) {
    parsed = undefined;
  } else {
    try { parsed = JSON.parse(text); }
    catch { parsed = text; }
  }
  return {
    method,
    url,
    status: res.status,
    headers: Object.fromEntries(res.headers.entries()),
    body: parsed,
    rawText: text,
  };
}

// ---------- Step / scenario execution --------------------------------------

async function runStep(config, openapi, step, vars, opts, scenarioName) {
  const stepName = step.name || `${step.request?.method || "GET"} ${step.request?.path || ""}`;
  const res = await performRequest(config, step, vars);

  if (opts.verbose) {
    console.error(`    -> ${res.method} ${res.url} -> ${res.status}`);
  }

  const errs = [];
  const expect = step.expect || {};

  // Status check.
  if (expect.status !== undefined) {
    const expected = Array.isArray(expect.status) ? expect.status : [expect.status];
    if (!expected.includes(res.status)) {
      errs.push(`status: expected ${expected.join(" or ")}, got ${res.status}`);
    }
  }

  // Schema validation.
  if (errs.length === 0 && expect.schema && res.body !== undefined) {
    let schema;
    if (typeof expect.schema === "string") {
      schema = getNamedSchema(openapi, expect.schema);
    } else {
      schema = expect.schema;
    }
    const schemaErrs = validate(res.body, schema, openapi, opts);
    errs.push(...schemaErrs);
  }

  // Body matching.
  if (errs.length === 0 && expect.body !== undefined) {
    const mode = expect.bodyMatch || "partial";
    const expectedBody = interpolate(expect.body, vars);
    errs.push(...matchBody(expectedBody, res.body, opts, mode));
  }

  if (errs.length > 0) {
    return {
      ok: false,
      stepName,
      errors: errs,
      response: res,
    };
  }

  // Captures.
  if (step.capture) {
    for (const [varName, pathExpr] of Object.entries(step.capture)) {
      try {
        let value = jsonPath(res.body, pathExpr);
        // Compatibility shim: when --accept-mongo-ids is set, fall back to
        // "_id" if the spec-style "id" sibling is missing. Lets fixtures be
        // written against the canonical OpenAPI shape even when the target
        // returns Mongoose-style envelopes.
        if (value === undefined && opts.acceptMongoIds && pathExpr.endsWith(".id")) {
          const fallback = pathExpr.slice(0, -3) + "._id";
          value = jsonPath(res.body, fallback);
        }
        vars[varName] = value;
        if (opts.verbose) {
          console.error(`       captured ${varName}=${JSON.stringify(value)}`);
        }
      } catch (e) {
        return {
          ok: false,
          stepName,
          errors: [`capture ${varName}: ${e.message}`],
          response: res,
        };
      }
    }
  }

  return { ok: true, stepName, response: res };
}

async function runScenario(config, openapi, fixture, opts) {
  // Auto-injected per-run variables. `run_nonce` is unique per scenario run
  // so fixtures can construct unique names without clashing across runs.
  const runNonce = `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
  const vars = {
    generalApiKey: config.generalApiKey,
    adminApiKey: config.adminApiKey,
    run_nonce: runNonce,
    ...(fixture.doc.vars || {}),
  };
  const steps = fixture.doc.steps || [];
  for (let i = 0; i < steps.length; i++) {
    const step = steps[i];
    const result = await runStep(config, openapi, step, vars, opts, fixture.name);
    if (!result.ok) {
      return {
        ok: false,
        stepIndex: i,
        stepName: result.stepName,
        errors: result.errors,
        response: result.response,
      };
    }
  }
  return { ok: true };
}

// ---------- Main -----------------------------------------------------------

async function main() {
  const config = parseArgs(process.argv.slice(2));
  let openapi;
  try {
    openapi = await loadOpenAPI(config.openapi);
  } catch (e) {
    console.error(`Failed to load openapi spec from ${config.openapi}: ${e.message}`);
    process.exit(2);
  }

  let fixtures;
  try {
    fixtures = await loadFixtures(config.fixturesDir, config.only);
  } catch (e) {
    console.error(`Failed to load fixtures from ${config.fixturesDir}: ${e.message}`);
    process.exit(2);
  }

  if (fixtures.length === 0) {
    console.error(`No fixtures found in ${config.fixturesDir}` +
                  (config.only ? ` matching --only ${config.only}` : ""));
    process.exit(2);
  }

  console.log(`HTMLTrust conformance suite`);
  console.log(`  target: ${config.targetUrl}${config.basePath}`);
  console.log(`  fixtures: ${fixtures.length}`);
  console.log(`  acceptMongoIds: ${config.acceptMongoIds}`);
  console.log("");

  let passed = 0;
  let failed = 0;
  for (const fx of fixtures) {
    const result = await runScenario(config, openapi, fx,
      { acceptMongoIds: config.acceptMongoIds, verbose: config.verbose });
    if (result.ok) {
      console.log(`PASS ${fx.name}`);
      passed++;
    } else {
      failed++;
      console.log(`FAIL ${fx.name}`);
      console.log(`  step ${result.stepIndex + 1}: ${result.stepName}`);
      for (const err of result.errors) {
        console.log(`    ${err}`);
      }
      if (result.response) {
        console.log(`    got status ${result.response.status}`);
        const bodyPreview = typeof result.response.body === "string"
          ? result.response.body
          : JSON.stringify(result.response.body);
        if (bodyPreview != null) {
          const truncated = bodyPreview.length > 800
            ? bodyPreview.slice(0, 800) + "...[truncated]"
            : bodyPreview;
          console.log(`    body: ${truncated}`);
        }
      }
    }
  }

  console.log("");
  console.log(`Result: ${passed} passed, ${failed} failed (${fixtures.length} total)`);
  process.exit(failed === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error(`Unexpected error: ${e.stack || e.message}`);
  process.exit(2);
});
