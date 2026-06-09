'use strict';

const fs = require('node:fs/promises');
const path = require('node:path');

function repoRoot() {
  return path.resolve(__dirname, '..');
}

function dataDir() {
  return process.env.RKSL_DATA_DIR || path.join(repoRoot(), 'data');
}

async function readJson(fileName, fallback) {
  try {
    const raw = await fs.readFile(path.join(dataDir(), fileName), 'utf8');
    return JSON.parse(raw || 'null') ?? fallback;
  } catch (error) {
    if (error.code === 'ENOENT') return fallback;
    throw error;
  }
}

async function writeJson(fileName, value) {
  await fs.mkdir(dataDir(), { recursive: true });
  await fs.writeFile(path.join(dataDir(), fileName), `${JSON.stringify(value, null, 2)}\n`, 'utf8');
}

function normalizeKey(row = {}) {
  return {
    id: row.id || row.source_id || row.sourceId || row.name || row.key_hash || row.keyHash,
    name: row.name || null,
    key_hash: row.key_hash || row.keyHash,
    script_id: row.script_id || row.scriptId,
    expires_at: row.expires_at || row.expiresAt || null,
    disabled: row.disabled === true,
    source: row.source || 'local',
    source_id: row.source_id || row.sourceId || null,
    issued_at: row.issued_at || row.issuedAt || null,
  };
}

function denormalizeKey(row = {}) {
  return {
    id: row.id || row.key_hash || row.keyHash,
    name: row.name || null,
    keyHash: row.key_hash || row.keyHash,
    scriptId: row.script_id || row.scriptId,
    expiresAt: row.expires_at || row.expiresAt || null,
    disabled: row.disabled === true,
    source: row.source || 'local',
    sourceId: row.source_id || row.sourceId || null,
    issuedAt: row.issued_at || row.issuedAt || null,
  };
}

async function listScriptRows() {
  const scriptsPath = path.join(repoRoot(), 'scripts');
  try {
    const entries = await fs.readdir(scriptsPath, { withFileTypes: true });
    return entries
      .filter((entry) => entry.isFile() && entry.name.endsWith('.luau'))
      .map((entry) => ({ id: path.basename(entry.name, '.luau') }))
      .sort((a, b) => a.id.localeCompare(b.id));
  } catch (error) {
    if (error.code === 'ENOENT') return [];
    throw error;
  }
}

async function loadScriptRows() {
  const rows = await listScriptRows();
  return Promise.all(rows.map(async (row) => ({
    id: row.id,
    code: await fs.readFile(path.join(repoRoot(), 'scripts', `${row.id}.luau`), 'utf8'),
  })));
}

async function loadScriptConfigRows() {
  const rows = new Map();
  const providers = [
    ['workink-links.json', 'workink'],
    ['lootlabs-links.json', 'lootlabs'],
    ['linkvertise-links.json', 'linkvertise'],
  ];

  for (const [fileName, provider] of providers) {
    const values = await readJson(fileName, {});
    for (const [scriptId, config] of Object.entries(values || {})) {
      const row = rows.get(scriptId) || { script_id: scriptId };
      if (provider === 'workink') {
        row.workink_enabled = config.enabled === true;
        row.workink_url = config.workInkUrl || config.workink_url || config.url || '';
        row.workink_link_id = config.linkId || config.workink_link_id || '';
      } else if (provider === 'lootlabs') {
        row.lootlabs_enabled = config.enabled === true;
        row.lootlabs_url = config.lootLabsUrl || config.lootlabs_url || config.url || '';
      } else if (provider === 'linkvertise') {
        row.linkvertise_enabled = config.enabled === true;
        row.linkvertise_url = config.linkvertiseUrl || config.linkvertise_url || config.url || '';
      }
      rows.set(scriptId, row);
    }
  }

  return [...rows.values()];
}

function makeQuery(rowsPromise, writer) {
  const state = { selects: null, filters: [], single: false, deleteMode: false };

  async function materialize() {
    let rows = await rowsPromise();
    for (const filter of state.filters) {
      rows = rows.filter((row) => {
        const value = row[filter.column];
        if (filter.op === 'eq') return String(value) === String(filter.value);
        if (filter.op === 'neq') return String(value) !== String(filter.value);
        return true;
      });
    }

    if (state.deleteMode && writer) {
      const before = await rowsPromise();
      const toDelete = new Set(rows.map((row) => JSON.stringify(row)));
      await writer(before.filter((row) => !toDelete.has(JSON.stringify(row))));
      return { data: null, error: null };
    }

    if (state.selects && state.selects !== '*') {
      const columns = state.selects.split(',').map((item) => item.trim()).filter(Boolean);
      rows = rows.map((row) => Object.fromEntries(columns.map((column) => [column, row[column]])));
    }

    if (state.single) return { data: rows[0] || null, error: null };
    return { data: rows, error: null };
  }

  return {
    select(columns = '*') { state.selects = columns; return this; },
    eq(column, value) { state.filters.push({ op: 'eq', column, value }); return this; },
    neq(column, value) { state.filters.push({ op: 'neq', column, value }); return this; },
    maybeSingle() { state.single = true; return this; },
    delete() { state.deleteMode = true; return this; },
    then(resolve, reject) { return materialize().then(resolve, reject); },
    catch(reject) { return materialize().catch(reject); },
  };
}

function createFileStoreClient() {
  const tableReaders = {
    scripts: loadScriptRows,
    script_configs: loadScriptConfigRows,
    keys: async () => (await readJson('keys.json', [])).map(normalizeKey),
    lootlabs_clicks: async () => readJson('lootlabs-clicks.json', []),
    lootlabs_postbacks: async () => readJson('lootlabs-postbacks.json', []),
    linkvertise_claims: async () => readJson('linkvertise-claims.json', []),
    banned_users: async () => readJson('banned-users.json', []),
    admin_settings: async () => readJson('admin-settings.json', []),
  };
  const tableWriters = {
    keys: async (rows) => writeJson('keys.json', rows.map(denormalizeKey)),
    lootlabs_clicks: async (rows) => writeJson('lootlabs-clicks.json', rows),
    lootlabs_postbacks: async (rows) => writeJson('lootlabs-postbacks.json', rows),
    linkvertise_claims: async (rows) => writeJson('linkvertise-claims.json', rows),
    banned_users: async (rows) => writeJson('banned-users.json', rows),
    admin_settings: async (rows) => writeJson('admin-settings.json', rows),
  };

  function reader(table) {
    return tableReaders[table] || (async () => []);
  }

  return {
    from(table) {
      return {
        select(columns = '*') { return makeQuery(reader(table), tableWriters[table]).select(columns); },
        delete() { return makeQuery(reader(table), tableWriters[table]).delete(); },
        async insert(payload) {
          const rows = await reader(table)();
          const items = Array.isArray(payload) ? payload : [payload];
          await tableWriters[table]([...
            rows,
            ...items.map((item) => ({ id: item.id || cryptoRandomId(), ...item })),
          ]);
          return { data: items, error: null };
        },
        async upsert(payload, options = {}) {
          const rows = await reader(table)();
          const items = Array.isArray(payload) ? payload : [payload];
          const conflictColumns = String(options.onConflict || 'id').split(',').map((item) => item.trim());
          for (const item of items) {
            const matchIndex = rows.findIndex((row) => conflictColumns.every((column) => String(row[column]) === String(item[column])));
            if (matchIndex === -1) rows.push({ id: item.id || cryptoRandomId(), ...item });
            else rows[matchIndex] = { ...rows[matchIndex], ...item };
          }
          await tableWriters[table](rows);
          return { data: items, error: null };
        },
      };
    },
  };
}

function cryptoRandomId() {
  return `local_${Date.now()}_${Math.random().toString(36).slice(2)}`;
}

module.exports = { createFileStoreClient };
