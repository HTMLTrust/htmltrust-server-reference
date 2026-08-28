#!/usr/bin/env node

/**
 * Upgrade indexes created by the pre-v1 reference server.
 *
 * MongoDB cannot replace an index with the same key pattern while its options
 * differ. The v1 ContentSignature identity is a partial unique index, so an
 * old database must drop the pre-v1 unique index before Mongoose can create
 * the v1 definition. Endorsement indexes were unique in an earlier release;
 * they are intentionally non-unique now so a revocation can coexist with the
 * endorsement it revokes.
 *
 * Run once with the same MONGO_URI used by the server:
 *   npm run migrate:v1
 */
const mongoose = require('mongoose');
const crypto = require('crypto');
const ContentSignature = require('../src/models/ContentSignature');
const Endorsement = require('../src/models/Endorsement');
const Key = require('../src/models/Key');
const SignerReport = require('../src/models/SignerReport');
const SignerVote = require('../src/models/SignerVote');

const CURRENT_INDEX_MODELS = [Key, ContentSignature, Endorsement, SignerVote, SignerReport];

const LEGACY_INDEXES = [
  [ContentSignature, 'contentHash_1_domain_1_authorId_1'],
  [Endorsement, 'contentHash_1_endorser_1'],
  [Endorsement, 'endorsement_1_endorser_1'],
];

const missingPublicId = {
  $or: [{ publicId: { $exists: false } }, { publicId: null }],
};

const newPublicId = () => `k_${crypto.randomBytes(18).toString('base64url')}`;

const backfillPublicIds = async () => {
  let updated = 0;
  const cursor = Key.collection.find(missingPublicId, { projection: { _id: 1 } });
  for await (const key of cursor) {
    const result = await Key.collection.updateOne(
      { _id: key._id, ...missingPublicId },
      { $set: { publicId: newPublicId() } },
    );
    updated += result.modifiedCount;
  }
  if (updated > 0) console.log(`backfilled ${updated} key public id(s)`);
  return updated;
};

const dropIfPresent = async (model, name) => {
  let indexes;
  try {
    indexes = await model.collection.indexes();
  } catch (error) {
    // A fresh deployment has no collection yet. createIndexes below will
    // create it with the current schema, so there is nothing to migrate.
    if (error.code === 26 || error.codeName === 'NamespaceNotFound') return false;
    throw error;
  }
  if (!indexes.some((index) => index.name === name)) return false;
  await model.collection.dropIndex(name);
  console.log(`dropped ${model.collection.name}.${name}`);
  return true;
};

const migrate = async () => {
  const mongoUri = process.env.MONGO_URI || 'mongodb://localhost:27017/content-signing';
  // Do not let Mongoose auto-create the replacement index before the legacy
  // one is dropped. MongoDB rejects two indexes with the same key pattern but
  // different options, which is the reason this migration exists.
  await mongoose.connect(mongoUri, { autoIndex: false });
  try {
    await backfillPublicIds();
    for (const [model, indexName] of LEGACY_INDEXES) {
      await dropIfPresent(model, indexName);
    }
    // Recreate the current partial/non-unique definitions without touching
    // unrelated indexes owned by an operator or another application.
    for (const model of CURRENT_INDEX_MODELS) {
      await model.createIndexes();
    }
    console.log('v1 index migration complete');
  } finally {
    await mongoose.disconnect();
  }
};

if (require.main === module) {
  migrate().catch((error) => {
    console.error(`v1 index migration failed: ${error.message}`);
    process.exitCode = 1;
  });
}

module.exports = { CURRENT_INDEX_MODELS, LEGACY_INDEXES, backfillPublicIds, dropIfPresent, migrate };
