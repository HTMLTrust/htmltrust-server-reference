/**
 * RFC 8785 JSON Canonicalization Scheme (JCS).
 *
 * The HTMLTrust draft (§10.2) defines the endorsement signing payload as the
 * JCS serialization of the endorsement document with the `signature` member
 * omitted. JCS is a precise specification, not "sorted keys" — getting it
 * wrong means signatures produced by conforming signers do not verify here.
 * The rules implemented below are:
 *
 *   §3.2.1  Whitespace between tokens is removed.
 *   §3.2.2.1 Literals: `null`, `true`, `false`.
 *   §3.2.2.2 Strings use the ECMAScript `JSON.stringify` escaping, including
 *            the ES2019 "well-formed" escaping of lone surrogates. Node's
 *            `JSON.stringify` implements exactly this, so it is used directly
 *            rather than reimplemented.
 *   §3.2.2.3 Numbers use the ECMAScript `Number::toString` algorithm, which is
 *            what `JSON.stringify` emits for finite numbers (including the
 *            `-0` -> `0` mapping JCS requires). Non-finite numbers are not
 *            representable in JSON and are rejected.
 *   §3.2.3   Object members are sorted by the UTF-16 code units of their
 *            names. JavaScript's relational operators on strings compare
 *            UTF-16 code units, so `<` is the specified ordering. (Note this
 *            is deliberately NOT code-point order — JCS differs from the
 *            claims canonicalization in draft §4.6, which sorts by UTF-8
 *            bytes.)
 *
 * Arrays keep their element order. Values that have no JSON representation
 * (`undefined`, functions, symbols) are dropped from objects and serialized as
 * `null` inside arrays, matching `JSON.stringify` semantics.
 */

/**
 * Sort object member names by UTF-16 code unit, per RFC 8785 §3.2.3.
 */
const byUtf16CodeUnit = (a, b) => {
  if (a === b) return 0;
  return a < b ? -1 : 1;
};

// Values JSON.stringify silently omits from objects and replaces with null
// inside arrays. BigInt is deliberately NOT in this set: JSON.stringify
// throws on it, and silently dropping a numeric field would change the
// signed payload without anyone noticing.
const isOmittable = (value) =>
  value === undefined || typeof value === "function" || typeof value === "symbol";

const serialize = (value, out) => {
  // Honour toJSON() the way JSON.stringify does, so Date and Mongoose
  // documents canonicalize as their JSON projection rather than their
  // internal shape.
  if (value !== null && typeof value === "object" && typeof value.toJSON === "function") {
    value = value.toJSON();
  }

  if (value === null) {
    out.push("null");
    return;
  }

  switch (typeof value) {
    case "boolean":
      out.push(value ? "true" : "false");
      return;
    case "number":
      if (!Number.isFinite(value)) {
        throw new Error("JCS: non-finite numbers cannot be canonicalized");
      }
      out.push(JSON.stringify(value));
      return;
    case "string":
      out.push(JSON.stringify(value));
      return;
    case "bigint":
      throw new Error("JCS: BigInt values cannot be canonicalized");
    default:
      break;
  }

  if (Array.isArray(value)) {
    out.push("[");
    for (let i = 0; i < value.length; i += 1) {
      if (i > 0) out.push(",");
      const element = value[i];
      // JSON.stringify replaces non-representable array elements with null.
      if (isOmittable(element)) out.push("null");
      else serialize(element, out);
    }
    out.push("]");
    return;
  }

  if (typeof value === "object") {
    const names = Object.keys(value)
      .filter((name) => !isOmittable(value[name]))
      .sort(byUtf16CodeUnit);
    out.push("{");
    for (let i = 0; i < names.length; i += 1) {
      if (i > 0) out.push(",");
      out.push(JSON.stringify(names[i]));
      out.push(":");
      serialize(value[names[i]], out);
    }
    out.push("}");
    return;
  }

  throw new Error(`JCS: unsupported value of type ${typeof value}`);
};

/**
 * Canonicalize a JSON value per RFC 8785.
 *
 * @param {unknown} value
 * @returns {string} the canonical serialization (a UTF-8 string)
 */
const canonicalizeJcs = (value) => {
  const out = [];
  serialize(value, out);
  return out.join("");
};

module.exports = { canonicalizeJcs };
