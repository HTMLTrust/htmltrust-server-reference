const test = require('node:test');
const assert = require('node:assert/strict');
const { assertDirectoryBaseUrl, directoryBaseUrl, directoryKeyUrl } = require('../src/utils/directoryUrl');

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

test('production directory URLs require an explicit HTTPS base URL', () => {
  assert.throws(
    () => assertDirectoryBaseUrl({ NODE_ENV: 'production' }),
    /must be set in production/,
  );
  assert.throws(
    () => assertDirectoryBaseUrl({ NODE_ENV: 'production', DIRECTORY_BASE_URL: 'http://directory.example' }),
    /must use https in production/,
  );
  assert.doesNotThrow(() => assertDirectoryBaseUrl({
    NODE_ENV: 'production',
    DIRECTORY_BASE_URL: 'https://directory.example',
  }));
});

test('development keeps the HTTP request-origin fallback', () => {
  assert.equal(directoryBaseUrl(request, { NODE_ENV: 'development' }), 'http://localhost:3000');
  assert.equal(directoryBaseUrl(request, {
    NODE_ENV: 'development',
    DIRECTORY_BASE_URL: 'http://directory.example',
  }), 'http://directory.example');
});
