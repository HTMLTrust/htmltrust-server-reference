const test = require('node:test');
const assert = require('node:assert/strict');
const SignerVote = require('../src/models/SignerVote');
const SignerReputation = require('../src/models/SignerReputation');
const SignerReport = require('../src/models/SignerReport');
const Key = require('../src/models/Key');
const { submitSignerVote } = require('../src/controllers/signerVoteController');
const { getSignerReputation } = require('../src/controllers/directoryController');

const original = {
  voteFindOne: SignerVote.findOne,
  voteFindOneAndUpdate: SignerVote.findOneAndUpdate,
  voteAggregate: SignerVote.aggregate,
  repFindOne: SignerReputation.findOne,
  reportCount: SignerReport.countDocuments,
  keyFindOne: Key.findOne,
};

const votes = new Map();
const reputations = new Map();
let voteNumber = 0;

function voteKey(voterId, signerId) {
  return `${voterId}\u0000${signerId}`;
}

function fakeResponse() {
  return {
    code: 200,
    body: null,
    status(code) { this.code = code; return this; },
    json(body) { this.body = body; return this; },
    set() { return this; },
    type() { return this; },
  };
}

function installFakes() {
  votes.clear();
  reputations.clear();
  voteNumber = 0;
  SignerVote.findOne = async ({ voterId, signerId }) => votes.get(voteKey(voterId, signerId)) || null;
  SignerVote.findOneAndUpdate = async ({ voterId, signerId }, update, options) => {
    const key = voteKey(voterId, signerId);
    const existing = votes.get(key);
    const previous = existing ? { ...existing } : null;
    if (existing) {
      existing.voteType = update.$set.voteType;
      if (update.$set.reason !== undefined) existing.reason = update.$set.reason;
      existing.updatedAt = new Date();
    } else if (options?.upsert) {
      votes.set(key, {
        _id: `vote-${++voteNumber}`,
        voterId,
        signerId,
        voteType: update.$set.voteType,
        reason: update.$set.reason,
        updatedAt: new Date(),
      });
    }
    return previous;
  };
  SignerVote.aggregate = async (pipeline) => {
    const signerId = pipeline[0].$match.signerId;
    const matching = [...votes.values()].filter((vote) => vote.signerId === signerId);
    if (matching.length === 0) return [];
    return [{
      count: matching.length,
      balance: matching.reduce((sum, vote) => sum + (vote.voteType === 'TRUST' ? 1 : -1), 0),
    }];
  };
  SignerReputation.findOne = ({ signerId }) => {
    const query = Promise.resolve(reputations.get(signerId) || null);
    query.lean = async () => reputations.get(signerId) || null;
    return query;
  };
  SignerReport.countDocuments = async () => 0;
  Key.findOne = async () => null;
}

function restoreFakes() {
  SignerVote.findOne = original.voteFindOne;
  SignerVote.findOneAndUpdate = original.voteFindOneAndUpdate;
  SignerVote.aggregate = original.voteAggregate;
  SignerReputation.findOne = original.repFindOne;
  SignerReport.countDocuments = original.reportCount;
  Key.findOne = original.keyFindOne;
}

function request(signerId, voteType, keyid, reason) {
  return {
    body: { signerId, voteType, ...(reason === undefined ? {} : { reason }) },
    htmltrustActor: { keyid },
  };
}

async function reputationScore(signerId) {
  const response = fakeResponse();
  await getSignerReputation({
    params: { id: signerId },
    protocol: 'https',
    get: () => 'directory-b.example',
  }, response);
  assert.equal(response.code, 200);
  return response.body.score;
}

test('external signer votes are idempotent, reversible, and independently keyed', async (t) => {
  installFakes();
  t.after(restoreFakes);

  const signerId = 'https://directory-a.example/keys/k_foreign_1234567890';
  const first = fakeResponse();
  await submitSignerVote(request(signerId, 'TRUST', 'https://voter-a.example/key'), first);
  assert.equal(first.code, 201);
  assert.equal(first.body.signerId, signerId);
  assert.equal(await reputationScore(signerId), 0.51);

  const repeat = fakeResponse();
  await submitSignerVote(request(signerId, 'TRUST', 'https://voter-a.example/key', 'same vote'), repeat);
  assert.equal(repeat.code, 200);
  assert.equal(repeat.body.previousVoteType, 'TRUST');
  assert.equal(await reputationScore(signerId), 0.51);
  assert.equal(votes.size, 1);

  const changed = fakeResponse();
  await submitSignerVote(request(signerId, 'DISTRUST', 'https://voter-a.example/key'), changed);
  assert.equal(changed.code, 200);
  assert.equal(changed.body.previousVoteType, 'TRUST');
  assert.equal(await reputationScore(signerId), 0.49);

  const independent = fakeResponse();
  await submitSignerVote(request(signerId, 'TRUST', 'https://voter-b.example/key'), independent);
  assert.equal(independent.code, 201);
  assert.equal(await reputationScore(signerId), 0.5);
  assert.equal(votes.size, 2);

  const getResponse = fakeResponse();
  await getSignerReputation({
    params: { id: signerId },
    protocol: 'https',
    get: () => 'directory-b.example',
  }, getResponse);
  assert.equal(getResponse.code, 200);
  assert.equal(getResponse.body.keyid, signerId);
  assert.equal(getResponse.body.score, 0.5);
});

test('canonical reputation lookup preserves percent escapes in an exact signer id', async (t) => {
  installFakes();
  t.after(restoreFakes);

  const signerId = 'https://directory-a.example/keys/name%2Fwith-escape';
  reputations.set(signerId, {
    signerId,
    trustScore: 0.6,
    verifiedSignatures: 0,
    reports: 0,
    updatedAt: new Date('2026-08-28T12:00:00Z'),
  });
  const response = fakeResponse();
  await getSignerReputation({
    // Express route parameters arrive decoded once. The literal percent
    // sequence belongs to the signer identifier and must remain untouched.
    params: { id: signerId },
    protocol: 'https',
    get: () => 'directory-b.example',
  }, response);

  assert.equal(response.code, 200);
  assert.equal(response.body.keyid, signerId);
  assert.equal(response.body.score, 0.6);
});

test('external signer votes reject invalid identifiers and vote types', async (t) => {
  installFakes();
  t.after(restoreFakes);

  for (const body of [
    { signerId: '', voteType: 'TRUST' },
    { signerId: ' https://directory.example/key', voteType: 'TRUST' },
    { signerId: 'https://directory.example/key\nsecond-line', voteType: 'TRUST' },
    { signerId: 'https://directory.example/key', voteType: 'MAYBE' },
  ]) {
    const response = fakeResponse();
    await submitSignerVote({ body }, response);
    assert.equal(response.code, 400);
  }
  assert.equal(votes.size, 0, 'invalid requests must not create vote records');
});

test('signer vote storage failures return a server error', async (t) => {
  installFakes();
  t.after(restoreFakes);
  SignerVote.findOneAndUpdate = async () => { throw new Error('storage unavailable'); };

  const result = fakeResponse();
  await submitSignerVote(request('https://directory.example/key', 'TRUST', 'https://voter.example/key'), result);
  assert.equal(result.code, 500);
  assert.equal(result.body.type, 'https://htmltrust.org/errors/storage-failure');
});
