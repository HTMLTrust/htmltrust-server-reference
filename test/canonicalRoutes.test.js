const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');

const serverSource = fs.readFileSync(require.resolve('../src/server'), 'utf8');
const endorsementSource = fs.readFileSync(require.resolve('../src/controllers/endorsementController'), 'utf8');

test('canonical endorsement creation returns a canonical resource Location', () => {
  assert.match(endorsementSource, /\.location\(`\/endorsements\/\$\{stored\._id\}`\)/);
  assert.doesNotMatch(endorsementSource, /\.location\(`\/api\/endorsements\/\$\{stored\._id\}`\)/);
});

test('canonical root exposes only the normative endorsement write', () => {
  assert.match(serverSource, /app\.post\(\s*['"]\/endorsements['"]/s);
  assert.doesNotMatch(serverSource, /app\.get\(\s*['"]\/endorsements['"]/s);
  assert.doesNotMatch(serverSource, /app\.delete\(\s*['"]\/endorsements\/:id['"]/s);
});
