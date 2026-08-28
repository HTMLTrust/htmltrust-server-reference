const test = require('node:test');
const assert = require('node:assert/strict');
const { negotiate } = require('../src/middleware/contentNegotiation');

const response = () => {
  const headers = {};
  const res = {
    headers,
    statusCode: 200,
    vary(name) { headers.Vary = name; return this; },
    set(name, value) { headers[name] = value; return this; },
    status(code) { this.statusCode = code; return this; },
    type(value) { headers['Content-Type'] = value; return this; },
    json(value) { this.body = value; return this; },
  };
  return res;
};

const request = (accept, contentType) => ({
  headers: {
    ...(accept === undefined ? {} : { accept }),
    ...(contentType === undefined ? {} : { 'content-type': contentType }),
  },
  accepts(types) {
    if (!accept) return types[0];
    return types.find((type) => accept === '*/*' || accept.split(',').map((part) => part.trim()).includes(type));
  },
});

test('canonical reads advertise cache semantics and vary on Accept', () => {
  const req = request('application/json');
  const res = response();
  let called = false;
  negotiate('application/htmltrust-content+json')(req, res, () => { called = true; });

  assert.equal(called, true);
  assert.equal(req.htmltrustResponseType, 'application/json');
  assert.equal(res.headers.Vary, 'Accept');
  assert.equal(res.headers['Cache-Control'], 'public, max-age=60, must-revalidate');
});

test('canonical responses retain the vendor media type by default', () => {
  const req = request(undefined);
  const res = response();
  negotiate('application/htmltrust-content+json')(req, res, () => {});

  assert.equal(req.htmltrustResponseType, 'application/htmltrust-content+json');
});

test('canonical endpoints reject an unacceptable representation', () => {
  const req = request('text/html');
  const res = response();
  negotiate('application/htmltrust-content+json')(req, res, () => {});

  assert.equal(res.statusCode, 406);
  assert.equal(res.body.type, 'https://htmltrust.org/errors/not-acceptable');
  assert.equal(res.headers.Vary, 'Accept');
});

test('canonical submissions require a JSON representation', () => {
  const req = request('application/json', 'text/plain');
  const res = response();
  negotiate('application/htmltrust-content+json', { requestBody: true })(req, res, () => {});

  assert.equal(res.statusCode, 415);
  assert.equal(res.body.type, 'https://htmltrust.org/errors/unsupported-media-type');
});
