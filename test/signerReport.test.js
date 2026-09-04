const test = require('node:test');
const assert = require('node:assert/strict');
const Key = require('../src/models/Key');
const SignerReputation = require('../src/models/SignerReputation');
const SignerReport = require('../src/models/SignerReport');
const SignerVote = require('../src/models/SignerVote');
const { getSignerReputation, reportSigner } = require('../src/controllers/directoryController');

const original = {
  directoryBaseUrl: process.env.DIRECTORY_BASE_URL,
  keyFindById: Key.findById,
  keyFindOne: Key.findOne,
  reputationFindOne: SignerReputation.findOne,
  reportCount: SignerReport.countDocuments,
  reportFindOne: SignerReport.findOne,
  reportUpdateOne: SignerReport.updateOne,
  voteAggregate: SignerVote.aggregate,
};

const reports = new Map();
const localKey = {
  _id: '507f1f77bcf86cd799439011',
  publicId: 'k_local_12345678901234567890',
  trustScore: 0.5,
  reports: 0,
  verifiedSignatures: 0,
  updatedAt: new Date('2026-08-28T12:00:00Z'),
};

function reportKey(filter) {
  return `${filter.reporterId}\u0000${filter.signerId}\u0000${filter.requestKey}`;
}

function response() {
  return {
    code: 200,
    body: null,
    status(code) { this.code = code; return this; },
    json(body) { this.body = body; return this; },
    set() { return this; },
    type() { return this; },
  };
}

function request({ signerId, keyId, idempotencyKey = 'request-1', reason = 'OTHER', evidence = 'https://evidence.example/item' }) {
  return {
    body: { ...(signerId ? { signerId } : {}), reason, evidence },
    params: keyId ? { keyId } : {},
    protocol: 'https',
    get(name) {
      if (name === 'Idempotency-Key') return idempotencyKey;
      if (name.toLowerCase() === 'host') return 'local.example';
      return undefined;
    },
  };
}

function installFakes() {
  process.env.DIRECTORY_BASE_URL = 'https://local.example';
  reports.clear();
  Key.findById = async () => null;
  Key.findOne = async (filter) => filter.publicId === localKey.publicId ? localKey : null;
  SignerReputation.findOne = () => {
    const query = Promise.resolve(null);
    query.lean = async () => null;
    return query;
  };
  SignerVote.aggregate = async () => [];
  SignerReport.updateOne = async (filter, update) => {
    const key = reportKey(filter);
    if (reports.has(key)) return { upsertedCount: 0 };
    reports.set(key, { ...update.$setOnInsert });
    return { upsertedCount: 1 };
  };
  SignerReport.findOne = (filter) => ({
    lean: async () => reports.get(reportKey(filter)) || null,
  });
  SignerReport.countDocuments = async ({ signerId }) =>
    [...reports.values()].filter((report) => report.signerId === signerId).length;
}

function restoreFakes() {
  if (original.directoryBaseUrl === undefined) delete process.env.DIRECTORY_BASE_URL;
  else process.env.DIRECTORY_BASE_URL = original.directoryBaseUrl;
  Key.findById = original.keyFindById;
  Key.findOne = original.keyFindOne;
  SignerReputation.findOne = original.reputationFindOne;
  SignerReport.countDocuments = original.reportCount;
  SignerReport.findOne = original.reportFindOne;
  SignerReport.updateOne = original.reportUpdateOne;
  SignerVote.aggregate = original.voteAggregate;
}

test('local canonical reports are idempotent and do not create a shadow reputation', async (t) => {
  installFakes();
  t.after(restoreFakes);
  const signerId = `https://local.example/keys/${localKey.publicId}`;

  const first = response();
  await reportSigner(request({ signerId }), first);
  assert.equal(first.code, 201);
  assert.match(first.body.reportId, /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i);

  const retry = response();
  await reportSigner(request({ signerId }), retry);
  assert.equal(retry.code, 200);
  assert.equal(retry.body.reportId, first.body.reportId);
  assert.equal(reports.size, 1);
  assert.equal(localKey.reports, 0, 'derived records replace mutable report counters');

  const read = response();
  await getSignerReputation({
    params: { id: signerId },
    protocol: 'https',
    get: () => 'local.example',
  }, read);
  assert.equal(read.code, 200);
  assert.equal(read.body.keyid, signerId);
  assert.equal(read.body.reports, 1);
  assert.equal(read.body.score, 0.45);

  const compatibilityRead = response();
  await getSignerReputation({
    params: { id: localKey.publicId },
    protocol: 'https',
    get: () => 'local.example',
  }, compatibilityRead);
  assert.equal(compatibilityRead.code, 200);
  assert.equal(compatibilityRead.body.reports, 1);
  assert.equal(compatibilityRead.body.score, 0.45);
});

test('foreign reports preserve exact percent escapes and validate the documented schema', async (t) => {
  installFakes();
  t.after(restoreFakes);
  const signerId = 'https://foreign.example/keys/name%2Fescaped';

  const accepted = response();
  await reportSigner(request({ signerId }), accepted);
  assert.equal(accepted.code, 201);
  assert.equal([...reports.values()][0].signerId, signerId);

  const badReason = response();
  await reportSigner(request({ signerId, idempotencyKey: 'request-2', reason: 'WHATEVER' }), badReason);
  assert.equal(badReason.code, 400);
  assert.equal(reports.size, 1);
});

test('the compatibility key report route returns 404 for an unknown local key', async (t) => {
  installFakes();
  t.after(restoreFakes);

  const result = response();
  await reportSigner(request({ keyId: 'k_unknown_12345678901234567890' }), result);
  assert.equal(result.code, 404);
  assert.deepEqual(result.body, {
    code: 'NOT_FOUND',
    message: 'No local key exists for the requested id',
  });
  assert.equal(reports.size, 0);
});

test('the compatibility key route rejects a misleading body signer id', async (t) => {
  installFakes();
  t.after(restoreFakes);

  const req = request({ keyId: localKey.publicId });
  req.body.signerId = 'https://foreign.example/keys/other';
  const result = response();
  await reportSigner(req, result);
  assert.equal(result.code, 400);
  assert.equal(result.body.code, 'BAD_REQUEST');
  assert.equal(typeof result.body.message, 'string');
  assert.equal(reports.size, 0);
});

test('signer report storage failures return a server error', async (t) => {
  installFakes();
  t.after(restoreFakes);
  SignerReport.updateOne = async () => { throw new Error('storage unavailable'); };

  const result = response();
  await reportSigner(request({ signerId: 'https://foreign.example/keys/failure' }), result);
  assert.equal(result.code, 500);
  assert.equal(result.body.type, 'https://htmltrust.org/errors/storage-failure');
});
