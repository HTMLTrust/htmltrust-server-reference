const test = require('node:test');
const assert = require('node:assert/strict');
const mongoose = require('mongoose');
const { MongoMemoryServer } = require('mongodb-memory-server');
const SignerReport = require('../src/models/SignerReport');
const SignerVote = require('../src/models/SignerVote');
const { getSignerReputation, reportSigner } = require('../src/controllers/directoryController');
const { submitSignerVote } = require('../src/controllers/signerVoteController');

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

test('concurrent vote and report retries leave one source-of-truth record', async (t) => {
  const mongod = await MongoMemoryServer.create();
  await mongoose.connect(mongod.getUri(), { dbName: 'signer-opinion-test' });
  await Promise.all([SignerVote.syncIndexes(), SignerReport.syncIndexes()]);
  t.after(async () => {
    await mongoose.disconnect();
    await mongod.stop();
  });

  const signerId = 'https://foreign.example/keys/k_concurrent_1234567890';
  const voteResponses = Array.from({ length: 20 }, response);
  await Promise.all(voteResponses.map((res) => submitSignerVote({
    body: { signerId, voteType: 'TRUST' },
    htmltrustActor: { keyid: 'https://voter.example/keys/one' },
  }, res)));
  assert.equal(await SignerVote.countDocuments({ signerId }), 1);
  assert.equal(voteResponses.filter((res) => res.code === 201).length, 1);
  assert.equal(voteResponses.every((res) => res.code === 200 || res.code === 201), true);

  const reportResponses = Array.from({ length: 20 }, response);
  await Promise.all(reportResponses.map((res) => reportSigner({
    body: {
      signerId,
      reason: 'OTHER',
      evidence: 'https://evidence.example/item',
    },
    params: {},
    get(name) {
      if (name === 'Idempotency-Key') return 'same-logical-report';
      if (name.toLowerCase() === 'host') return 'directory.example';
      return undefined;
    },
    protocol: 'https',
  }, res)));
  assert.equal(await SignerReport.countDocuments({ signerId }), 1);
  assert.equal(reportResponses.filter((res) => res.code === 201).length, 1);
  assert.equal(reportResponses.every((res) => res.code === 200 || res.code === 201), true);

  const read = response();
  await getSignerReputation({
    params: { id: signerId },
    protocol: 'https',
    get: () => 'directory.example',
  }, read);
  assert.equal(read.code, 200);
  assert.equal(read.body.reports, 1);
  assert.equal(read.body.score, 0.46);
});
