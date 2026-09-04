const test = require('node:test');
const assert = require('node:assert/strict');
const SignerReputation = require('../src/models/SignerReputation');

test('external signer reputation stores an exact foreign keyid without local key custody', () => {
  const signerId = 'https://directory-a.example/keys/k_external_1234567890';
  const reputation = new SignerReputation({ signerId, reports: 2, trustScore: 0.35 });

  assert.equal(reputation.validateSync(), undefined);
  assert.equal(reputation.signerId, signerId);
  assert.equal(reputation.publicKey, undefined);
  assert.equal(reputation.authorId, undefined);
});

test('external signer reputation rejects an empty or oversized identifier', () => {
  assert.notEqual(new SignerReputation({ signerId: '' }).validateSync(), undefined);
  assert.notEqual(new SignerReputation({ signerId: 'x'.repeat(2049) }).validateSync(), undefined);
});
