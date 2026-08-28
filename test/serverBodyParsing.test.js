const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const fs = require('node:fs');

const serverSource = fs.readFileSync(require.resolve('../src/server'), 'utf8');

const postJson = async (contentType, body) => {
  const app = express();
  app.use(express.json({
    type: ['application/json', 'application/*+json'],
    verify: (req, res, rawBody) => {
      req.rawBody = rawBody;
    },
  }));
  app.post('/', (req, res) => res.json({ body: req.body, rawBody: req.rawBody.toString('utf8') }));

  const server = app.listen(0);
  try {
    const { port } = server.address();
    const response = await fetch(`http://127.0.0.1:${port}/`, {
      method: 'POST',
      headers: { 'content-type': contentType },
      body,
    });
    return { status: response.status, body: await response.json() };
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
};

test('server JSON body parsing accepts vendor +json media types', async () => {
  assert.match(
    serverSource,
    /type:\s*\[\s*['"]application\/json['"]\s*,\s*['"]application\/\*\+json['"]\s*\]/,
  );

  const response = await postJson('application/htmltrust-content+json', '{"contentHash":"sha256:test"}');
  assert.equal(response.status, 200);
  assert.deepEqual(response.body.body, { contentHash: 'sha256:test' });
  assert.equal(response.body.rawBody, '{"contentHash":"sha256:test"}');
});

test('server JSON body parsing preserves application/json behavior', async () => {
  const response = await postJson('application/json', '{"contentHash":"sha256:compat"}');
  assert.equal(response.status, 200);
  assert.deepEqual(response.body.body, { contentHash: 'sha256:compat' });
  assert.equal(response.body.rawBody, '{"contentHash":"sha256:compat"}');
});
