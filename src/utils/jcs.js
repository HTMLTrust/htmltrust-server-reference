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
 *   §3.2.2.2 Strings use ECMAScript JSON escaping. Lone UTF-16 surrogates are
 *            rejected because RFC 8785 requires I-JSON input and explicitly
 *            treats them as invalid Unicode data.
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
 * Arrays keep their element order. Values outside the JSON data model are
 * rejected rather than silently changing a signed payload.
 */

/**
 * Sort object member names by UTF-16 code unit, per RFC 8785 §3.2.3.
 */
const byUtf16CodeUnit = (a, b) => {
  if (a === b) return 0;
  return a < b ? -1 : 1;
};

const assertUnicodeScalarString = (value) => {
  for (let index = 0; index < value.length; index += 1) {
    const unit = value.charCodeAt(index);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) {
        throw new Error("JCS: string contains a lone UTF-16 surrogate");
      }
      index += 1;
    } else if (unit >= 0xdc00 && unit <= 0xdfff) {
      throw new Error("JCS: string contains a lone UTF-16 surrogate");
    }
  }
};

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
      assertUnicodeScalarString(value);
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
      serialize(value[i], out);
    }
    out.push("]");
    return;
  }

  if (typeof value === "object") {
    const names = Object.keys(value).sort(byUtf16CodeUnit);
    out.push("{");
    for (let i = 0; i < names.length; i += 1) {
      if (i > 0) out.push(",");
      assertUnicodeScalarString(names[i]);
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
