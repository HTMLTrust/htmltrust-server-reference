const test = require("node:test");
const assert = require("node:assert/strict");
const { canonicalizeJcs } = require("../src/utils/jcs");

// RFC 8785 section 3.2.3: object member names are sorted by their UTF-16 code
// units. The astral key below is the case that distinguishes UTF-16 code-unit
// order (what JCS specifies) from code-point order (what the claims
// canonicalization in draft section 4.6 specifies): the lead surrogate U+D83D
// sorts before U+FB00, while the code point U+1F602 does not.
test("JCS sorts member names by UTF-16 code unit", () => {
  const keys = [
    "€",
    "\r",
    "\n",
    "1",
    "",
    "ö",
    "Č",
    " ",
    "😂",
    "A",
    "Å",
    "ﬀ",
  ];
  const input = {};
  keys.forEach((key, index) => {
    input[key] = index;
  });

  const expected = [...keys].sort((a, b) => (a === b ? 0 : a < b ? -1 : 1));
  const want = `{${expected.map((k) => `${JSON.stringify(k)}:${input[k]}`).join(",")}}`;
  const got = canonicalizeJcs(input);

  assert.equal(got, want);
  assert.ok(got.indexOf("😂") < got.indexOf("ﬀ"));
});

test("JCS serializes numbers per ECMAScript Number::toString", () => {
  assert.equal(
    canonicalizeJcs([333333333.33333329, 1e30, 4.5, 2e-3, 1e-27, -0]),
    "[333333333.3333333,1e+30,4.5,0.002,1e-27,0]",
  );
});

test("JCS escapes strings exactly like JSON.stringify", () => {
  const value = "€$\nA'B\"\\\\\"/";
  assert.equal(canonicalizeJcs({ s: value }), `{"s":${JSON.stringify(value)}}`);
  assert.equal(canonicalizeJcs(""), '"\\u000f"');
  assert.equal(canonicalizeJcs("\n"), '"\\n"');
});

test("JCS rejects lone UTF-16 surrogates", () => {
  assert.throws(() => canonicalizeJcs("\ud800"), /surrogate/);
  assert.throws(() => canonicalizeJcs("\udfff"), /surrogate/);
  assert.throws(() => canonicalizeJcs({ "\ud800": 1 }), /surrogate/);
});

test("JCS emits no insignificant whitespace and preserves array order", () => {
  assert.equal(canonicalizeJcs({ b: [3, 1, 2], a: 1 }), '{"a":1,"b":[3,1,2]}');
});

test("JCS is idempotent through a JSON round trip", () => {
  const value = { b: [1, { z: null, a: true }], a: "x" };
  const once = canonicalizeJcs(value);
  assert.equal(canonicalizeJcs(JSON.parse(once)), once);
});

test("JCS rejects values with no JSON representation", () => {
  assert.throws(() => canonicalizeJcs({ a: Infinity }));
  assert.throws(() => canonicalizeJcs({ a: NaN }));
  assert.throws(() => canonicalizeJcs({ a: 1n }));
  assert.throws(() => canonicalizeJcs({ a: undefined }));
  assert.throws(() => canonicalizeJcs([undefined]));
});
