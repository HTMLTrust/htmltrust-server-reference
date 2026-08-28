const test = require('node:test');
const assert = require('node:assert/strict');
const { directoryBaseUrl, directoryKeyUrl } = require('../src/utils/directoryUrl');

const request = {
  protocol: 'http',
  get(name) {
    assert.equal(name, 'host');
    return 'localhost:3000';
  },
};

test('directory URLs fall back to the request origin', () => {
  assert.equal(directoryBaseUrl(request, {}), 'http://localhost:3000');
  assert.equal(directoryKeyUrl(request, 'key 1', {}), 'http://localhost:3000/keys/key%201');
});

test('directory URLs use the configured public base URL', () => {
  const env = { DIRECTORY_BASE_URL: 'https://directory.example/' };
  assert.equal(directoryBaseUrl(request, env), 'https://directory.example');
  assert.equal(directoryKeyUrl(request, 'abc', env), 'https://directory.example/keys/abc');
});

test('directory URLs reject unsupported configured schemes', () => {
  assert.throws(
    () => directoryBaseUrl(request, { DIRECTORY_BASE_URL: 'file:///srv/directory' }),
    /must use http or https/,
  );
});
