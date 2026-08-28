const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');

const serverSource = fs.readFileSync(require.resolve('../src/server'), 'utf8');
const endorsementSource = fs.readFileSync(require.resolve('../src/controllers/endorsementController'), 'utf8');
const openapiSource = fs.readFileSync(require.resolve('../openapi.yaml'), 'utf8');

test('canonical endorsement creation returns a canonical resource Location', () => {
  assert.match(endorsementSource, /\.location\(`\/endorsements\/\$\{stored\._id\}`\)/);
  assert.doesNotMatch(endorsementSource, /\.location\(`\/api\/endorsements\/\$\{stored\._id\}`\)/);
});

test('canonical root exposes only the normative endorsement write', () => {
  assert.match(serverSource, /app\.post\(\s*['"]\/endorsements['"]/s);
  assert.doesNotMatch(serverSource, /app\.get\(\s*['"]\/endorsements['"]/s);
  assert.doesNotMatch(serverSource, /app\.delete\(\s*['"]\/endorsements\/:id['"]/s);
});

test('canonical root route and OpenAPI path sets match the seven normative operations', () => {
  for (const pattern of [
    /app\.get\(\s*['"]\/.well-known\/htmltrust['"]/s,
    /app\.get\(\s*['"]\/content\/:contentHash['"]/s,
    /app\.post\(\s*['"]\/content['"]/s,
    /app\.get\(\s*['"]\/content\/:contentHash\/endorsements['"]/s,
    /app\.post\(\s*['"]\/endorsements['"]/s,
    /app\.get\(\s*['"]\/keys\/:id['"]/s,
    /app\.get\(\s*['"]\/signers\/:id\/reputation['"]/s,
  ]) {
    assert.match(serverSource, pattern);
  }

  const paths = [...openapiSource.matchAll(/^  (\/[^:]+):$/gm)].map((match) => match[1]);
  assert.deepEqual(
    paths.filter((path) => !path.startsWith('/api/')),
    [
      '/.well-known/htmltrust',
      '/keys/{id}',
      '/signers/{id}/reputation',
      '/content',
      '/content/{hash}',
      '/content/{hash}/endorsements',
      '/endorsements',
    ],
  );
});
