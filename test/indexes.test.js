const test = require('node:test');
const assert = require('node:assert/strict');
const ContentSignature = require('../src/models/ContentSignature');
const Endorsement = require('../src/models/Endorsement');
const { LEGACY_INDEXES } = require('../scripts/migrate-v1-indexes');

test('v1 content identity uses a partial unique index', () => {
  const index = ContentSignature.schema.indexes().find(([keys]) =>
    keys.contentHash === 1 && keys.profile === 1 && keys.location === 1 && keys.keyid === 1);
  assert.ok(index, 'v1 identity index is declared');
  assert.equal(index[1].unique, true);
  assert.deepEqual(index[1].partialFilterExpression, { profile: 'htmltrust-signature-v1' });
  const legacy = ContentSignature.schema.indexes().find(([keys]) =>
    keys.contentHash === 1 && keys.domain === 1 && keys.authorId === 1);
  assert.deepEqual(legacy[1].partialFilterExpression.profile, { $in: [null] });
});

test('pre-v1 index names are covered by the explicit migration', () => {
  const names = LEGACY_INDEXES.map(([, name]) => name);
  assert.deepEqual(names, [
    'contentHash_1_domain_1_authorId_1',
    'contentHash_1_endorser_1',
    'endorsement_1_endorser_1',
  ]);
  const endorsementIndexes = Endorsement.schema.indexes();
  assert.ok(endorsementIndexes.some(([keys, options]) =>
    keys.contentHash === 1 && keys.endorser === 1 && options?.unique !== true));
  assert.ok(endorsementIndexes.some(([keys, options]) =>
    keys.endorsement === 1 && keys.endorser === 1 && options?.unique !== true));
});
