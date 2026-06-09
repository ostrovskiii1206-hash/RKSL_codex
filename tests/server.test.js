'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const { createServer } = require('../server');

function listen(server) {
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      resolve(`http://${address.address}:${address.port}`);
    });
  });
}

async function withServer(callback) {
  const server = createServer();
  const baseUrl = await listen(server);
  try {
    await callback(baseUrl);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
}

test('health endpoint returns service status', async () => {
  await withServer(async (baseUrl) => {
    const response = await fetch(`${baseUrl}/api/health`);
    const payload = await response.json();

    assert.equal(response.status, 200);
    assert.equal(payload.status, 'success');
    assert.equal(payload.service, 'RKSL');
  });
});

test('script list includes NBTF_ACTIVE', async () => {
  await withServer(async (baseUrl) => {
    const response = await fetch(`${baseUrl}/api/scripts`);
    const payload = await response.json();

    assert.equal(response.status, 200);
    assert.deepEqual(payload.scripts, ['NBTF_ACTIVE']);
  });
});

test('valid local key returns the matching script', async () => {
  await withServer(async (baseUrl) => {
    const response = await fetch(`${baseUrl}/api/check-key`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ key: 'DEMO-RKSL-KEY', scriptId: 'NBTF_ACTIVE' }),
    });
    const payload = await response.json();

    assert.equal(response.status, 200);
    assert.equal(payload.status, 'success');
    assert.equal(payload.code, 'KEY_VALID');
    assert.equal(payload.scriptId, 'NBTF_ACTIVE');
    assert.match(payload.script, /print\('hello world'\)/);
  });
});

test('invalid local key is rejected', async () => {
  await withServer(async (baseUrl) => {
    const response = await fetch(`${baseUrl}/api/check-key`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ key: 'wrong-key', scriptId: 'NBTF_ACTIVE' }),
    });
    const payload = await response.json();

    assert.equal(response.status, 403);
    assert.equal(payload.status, 'error');
    assert.equal(payload.code, 'KEY_INVALID');
  });
});

test('bad json receives explicit loader status', async () => {
  await withServer(async (baseUrl) => {
    const response = await fetch(`${baseUrl}/api/check-key`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: '{ bad json',
    });
    const payload = await response.json();

    assert.equal(response.status, 400);
    assert.equal(payload.code, 'BAD_JSON');
  });
});


test('LootLabs postback issues a key for a started click', async () => {
  const previousDataDir = process.env.RKSL_DATA_DIR;
  const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'rksl-lootlabs-'));
  process.env.RKSL_DATA_DIR = tempDir;
  await fs.writeFile(path.join(tempDir, 'keys.json'), '[]\n', 'utf8');
  await fs.writeFile(path.join(tempDir, 'lootlabs-links.json'), JSON.stringify({
    NBTF_ACTIVE: {
      scriptId: 'NBTF_ACTIVE',
      lootLabsUrl: 'https://loot-link.com/s/demo',
      enabled: true,
    },
  }), 'utf8');

  try {
    await withServer(async (baseUrl) => {
      const startResponse = await fetch(`${baseUrl}/lootlabs-start?script=NBTF_ACTIVE`, { redirect: 'manual' });
      assert.equal(startResponse.status, 302);
      const location = startResponse.headers.get('location');
      assert.match(location, /^https:\/\/loot-link\.com\/s\/demo\?puid=rksl_/);
      const cookie = startResponse.headers.get('set-cookie');
      assert.match(cookie, /rksl_lootlabs_click=rksl_/);
      const clickId = new URL(location).searchParams.get('puid');

      const postbackResponse = await fetch(`${baseUrl}/api/lootlabs-postback?click_id=${encodeURIComponent(clickId)}&ip=127.0.0.1&unique_id=uniq-1`);
      const postbackPayload = await postbackResponse.json();
      assert.equal(postbackResponse.status, 200);
      assert.equal(postbackPayload.status, 'success');
      assert.equal(postbackPayload.provider, 'lootlabs');
      assert.equal(postbackPayload.scriptId, 'NBTF_ACTIVE');

      const claimResponse = await fetch(`${baseUrl}/lootlabs-claim`, { headers: { Cookie: cookie } });
      const claimHtml = await claimResponse.text();
      const key = claimHtml.match(/RKSL-LL-[A-Z0-9_-]+/)[0];

      const checkResponse = await fetch(`${baseUrl}/api/check-key`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ key, scriptId: 'NBTF_ACTIVE' }),
      });
      const checkPayload = await checkResponse.json();
      assert.equal(checkResponse.status, 200);
      assert.equal(checkPayload.code, 'KEY_VALID');
      assert.equal(checkPayload.source, 'lootlabs');
    });
  } finally {
    if (previousDataDir) {
      process.env.RKSL_DATA_DIR = previousDataDir;
    } else {
      delete process.env.RKSL_DATA_DIR;
    }
    await fs.rm(tempDir, { recursive: true, force: true });
  }
});


test('Linkvertise anti-bypass claim issues a key after hash verification', async () => {
  const previousDataDir = process.env.RKSL_DATA_DIR;
  const previousSkipVerify = process.env.LINKVERTISE_SKIP_VERIFY;
  const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'rksl-linkvertise-'));
  process.env.RKSL_DATA_DIR = tempDir;
  process.env.LINKVERTISE_SKIP_VERIFY = 'true';
  await fs.writeFile(path.join(tempDir, 'keys.json'), '[]\n', 'utf8');
  await fs.writeFile(path.join(tempDir, 'linkvertise-links.json'), JSON.stringify({
    NBTF_ACTIVE: {
      scriptId: 'NBTF_ACTIVE',
      linkvertiseUrl: 'https://link-hub.net/6310451/W8TcShdFOC3G',
      enabled: true,
    },
  }), 'utf8');

  try {
    await withServer(async (baseUrl) => {
      const startResponse = await fetch(`${baseUrl}/linkvertise-start?script=NBTF_ACTIVE`, { redirect: 'manual' });
      assert.equal(startResponse.status, 302);
      assert.equal(startResponse.headers.get('location'), 'https://link-hub.net/6310451/W8TcShdFOC3G');

      const hash = 'a'.repeat(64);
      const claimResponse = await fetch(`${baseUrl}/linkvertise-claim?script=NBTF_ACTIVE&hash=${hash}`, { redirect: 'manual' });
      assert.equal(claimResponse.status, 302);
      const claimLocation = claimResponse.headers.get('location');
      assert.match(claimLocation, /^\/linkvertise-key\?claim_id=lv_/);
      const cookie = claimResponse.headers.get('set-cookie');
      assert.match(cookie, /rksl_linkvertise_claim=lv_/);

      const keyResponse = await fetch(`${baseUrl}${claimLocation}`, { headers: { Cookie: cookie } });
      const keyHtml = await keyResponse.text();
      const key = keyHtml.match(/RKSL-LV-[A-Z0-9_-]+/)[0];

      const checkResponse = await fetch(`${baseUrl}/api/check-key`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ key, scriptId: 'NBTF_ACTIVE' }),
      });
      const checkPayload = await checkResponse.json();
      assert.equal(checkResponse.status, 200);
      assert.equal(checkPayload.code, 'KEY_VALID');
      assert.equal(checkPayload.source, 'linkvertise');
    });
  } finally {
    if (previousDataDir) {
      process.env.RKSL_DATA_DIR = previousDataDir;
    } else {
      delete process.env.RKSL_DATA_DIR;
    }
    if (previousSkipVerify) {
      process.env.LINKVERTISE_SKIP_VERIFY = previousSkipVerify;
    } else {
      delete process.env.LINKVERTISE_SKIP_VERIFY;
    }
    await fs.rm(tempDir, { recursive: true, force: true });
  }
});
