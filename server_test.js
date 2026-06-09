'use strict';

require('dotenv').config();
const { createServer } = require('./server');

async function main() {
  const port = Number(process.env.SERVER_TEST_PORT || 3100);
  const server = createServer();

  await new Promise((resolve) => server.listen(port, '127.0.0.1', resolve));
  const baseUrl = `http://127.0.0.1:${port}`;

  try {
    const health = await fetch(`${baseUrl}/api/health`);
    console.log('health', health.status, await health.text());

    if (process.env.RKSL_TEST_KEY) {
      const check = await fetch(`${baseUrl}/api/check-key`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ key: process.env.RKSL_TEST_KEY, scriptId: process.env.RKSL_TEST_SCRIPT_ID || 'NBTF_ACTIVE' }),
      });
      console.log('check-key', check.status, await check.text());
    } else {
      console.log('RKSL_TEST_KEY is empty; skipped /api/check-key smoke check.');
    }
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
