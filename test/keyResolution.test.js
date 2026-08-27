const test = require("node:test");
const assert = require("node:assert/strict");
const { resolveKeyId } = require("../src/utils/keyResolution");

test("remote key resolution stops reading after the 64 KiB limit", async () => {
  const previousFetch = global.fetch;
  const previousEnabled = process.env.HTMLTRUST_REMOTE_KEY_RESOLUTION;
  const previousConsoleError = console.error;
  let pulls = 0;
  let cancelled = false;
  const stream = new ReadableStream({
    pull(controller) {
      pulls += 1;
      controller.enqueue(new Uint8Array(32 * 1024));
    },
    cancel() {
      cancelled = true;
    },
  });
  global.fetch = async () => new Response(stream, { status: 200 });
  console.error = () => {};
  process.env.HTMLTRUST_REMOTE_KEY_RESOLUTION = "1";

  try {
    const resolved = await resolveKeyId("https://93.184.216.34/key.json");
    assert.equal(resolved, null);
    assert.ok(pulls <= 4, `expected bounded streaming reads, read ${pulls} chunks`);
    assert.equal(cancelled, true);
  } finally {
    global.fetch = previousFetch;
    console.error = previousConsoleError;
    if (previousEnabled === undefined) delete process.env.HTMLTRUST_REMOTE_KEY_RESOLUTION;
    else process.env.HTMLTRUST_REMOTE_KEY_RESOLUTION = previousEnabled;
  }
});
