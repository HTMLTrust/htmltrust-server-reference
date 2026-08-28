const test = require('node:test');
const assert = require('node:assert/strict');

const ContentSignature = require('../src/models/ContentSignature');
const Endorsement = require('../src/models/Endorsement');
const Key = require('../src/models/Key');
const contentController = require('../src/controllers/contentController');
const directoryController = require('../src/controllers/directoryController');
const endorsementController = require('../src/controllers/endorsementController');

const validHash = `sha256:${Buffer.alloc(32).toString('base64').replace(/=+$/, '')}`;

const response = () => ({
  statusCode: 200,
  headers: {},
  status(code) { this.statusCode = code; return this; },
  set(name, value) { this.headers[name] = value; return this; },
  type(value) { this.headers['Content-Type'] = value; return this; },
  json(value) { this.body = value; return this; },
  send(value) { this.body = value; return this; },
});

const withStub = async (object, property, replacement, callback) => {
  const original = object[property];
  object[property] = replacement;
  const originalError = console.error;
  console.error = () => {};
  try {
    await callback();
  } finally {
    console.error = originalError;
    object[property] = original;
  }
};

test('content read failures return a generic 500 problem', async () => {
  await withStub(ContentSignature, 'find', () => ({
    sort: async () => { throw new Error('database exploded'); },
  }), async () => {
    for (const handler of [contentController.getContentRecord, contentController.getContentRecordV1]) {
      const res = response();
      await handler({ params: { contentHash: validHash } }, res);
      assert.equal(res.statusCode, 500);
      assert.equal(res.body.type, 'https://htmltrust.org/errors/storage-failure');
      assert.doesNotMatch(res.body.detail, /database exploded/);
    }
  });
});

test('endorsement read failures return a generic 500 problem', async () => {
  await withStub(Endorsement, 'find', () => ({
    sort: async () => { throw new Error('database exploded'); },
  }), async () => {
    const listResponse = response();
    await endorsementController.listEndorsements({ query: { 'content-hash': validHash } }, listResponse);
    assert.equal(listResponse.statusCode, 500);
    assert.equal(listResponse.body.type, 'https://htmltrust.org/errors/storage-failure');

    const nestedResponse = response();
    await contentController.listContentEndorsements(
      { params: { contentHash: validHash } },
      nestedResponse,
    );
    assert.equal(nestedResponse.statusCode, 500);
    assert.equal(nestedResponse.body.type, 'https://htmltrust.org/errors/storage-failure');
  });
});

test('key read failures return a generic 500 problem', async () => {
  await withStub(Key, 'findById', async () => { throw new Error('database exploded'); }, async () => {
    const res = response();
    await directoryController.getKeyDocument({ params: { id: 'a'.repeat(24) } }, res);
    assert.equal(res.statusCode, 500);
    assert.equal(res.body.type, 'https://htmltrust.org/errors/storage-failure');
    assert.doesNotMatch(res.body.detail, /database exploded/);
  });
});

test('endorsement delete storage failures return a generic 500 problem', async () => {
  await withStub(Endorsement, 'findById', async () => { throw new Error('database exploded'); }, async () => {
    const res = response();
    await endorsementController.deleteEndorsement(
      { params: { id: 'b'.repeat(24) } },
      res,
    );
    assert.equal(res.statusCode, 500);
    assert.equal(res.body.type, 'https://htmltrust.org/errors/storage-failure');
  });
});

test('malformed read identifiers still return 400 before database access', async () => {
  let queried = false;
  await withStub(Key, 'findById', async () => { queried = true; }, async () => {
    const keyResponse = response();
    await directoryController.getKeyDocument({ params: { id: 'not-an-object-id' } }, keyResponse);
    assert.equal(keyResponse.statusCode, 400);
    assert.equal(queried, false);
  });

  const contentResponse = response();
  await contentController.getContentRecordV1({ params: { contentHash: 'bad' } }, contentResponse);
  assert.equal(contentResponse.statusCode, 400);
});
