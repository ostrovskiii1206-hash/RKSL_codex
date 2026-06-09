'use strict';

const fs = require('node:fs/promises');
const path = require('node:path');
const { createClient } = require('@supabase/supabase-js');
const WebSocket = require('ws');

// === НАСТРОЙКИ ПОДКЛЮЧЕНИЯ ===
const SUPABASE_URL = 'https://pxeftgkoqepoopghqeyd.supabase.co';
const SUPABASE_SERVICE_ROLE_KEY = 'sb_secret_u3lgavzJsLRUFlxzGaceCA_dYpZUavz';

if (SUPABASE_SERVICE_ROLE_KEY === 'Хуета') {
  console.error('Ошибка: SUPABASE_SERVICE_ROLE_KEY Хуевый !');
  process.exit(1);
}

const supabase = createClient(
  SUPABASE_URL,
  SUPABASE_SERVICE_ROLE_KEY,
  {
    realtime: {
      transport: WebSocket
    }
  }
);

// Вспомогательная функция для безопасного чтения JSON с автопоиском в корне или папке data/
async function readJsonFallback(filename) {
  const paths = [
    path.join(process.cwd(), filename),
    path.join(process.cwd(), 'data', filename)
  ];
  for (const p of paths) {
    try {
      const raw = await fs.readFile(p, 'utf8');
      return JSON.parse(raw);
    } catch (err) {
      // Игнорируем ошибку и пробуем следующий путь
    }
  }
  return null;
}

// Сравнение дат с учетом разницы таймзон/форматов строк
function isDateEqual(d1, d2) {
  if (!d1 && !d2) return true;
  if (!d1 || !d2) return false;
  return new Date(d1).getTime() === new Date(d2).getTime();
}

async function syncScripts() {
  console.log('--- Синхронизация скриптов (*.luau) ---');
  
  // Ищем папку со скриптами в корне или внутри папки data/
  let scriptsDir = path.join(process.cwd(), 'scripts');
  try {
    await fs.access(scriptsDir);
  } catch {
    scriptsDir = path.join(process.cwd(), 'data', 'scripts');
  }

  let files = [];
  try {
    files = await fs.readdir(scriptsDir);
  } catch (err) {
    console.warn(`Папка scripts не найдена по путям. Пропуск синхронизации кода скриптов.`);
    return;
  }

  const luauFiles = files.filter(f => f.endsWith('.luau'));
  
  for (const file of luauFiles) {
    const scriptId = path.basename(file, '.luau');
    const localCode = await fs.readFile(path.join(scriptsDir, file), 'utf8');

    // Проверяем, есть ли скрипт в БД и отличается ли код
    const { data: dbScript, error } = await supabase
      .from('scripts')
      .select('code')
      .eq('id', scriptId)
      .maybeSingle();

    if (error) {
      console.error(`Ошибка при получении скрипта ${scriptId}:`, error.message);
      continue;
    }

    if (!dbScript || dbScript.code !== localCode) {
      console.log(`Обновление кода скрипта: ${scriptId}...`);
      const { error: upsertErr } = await supabase
        .from('scripts')
        .upsert({ id: scriptId, code: localCode });

      if (upsertErr) {
        console.error(`Ошибка при обновлении ${scriptId}:`, upsertErr.message);
      } else {
        console.log(`Успешно обновлен скрипт ${scriptId}`);
      }
    } else {
      console.log(`Скрипт ${scriptId} уже актуален, пропускаем.`);
    }
  }
}

async function syncScriptConfigs() {
  console.log('\n--- Синхронизация конфигураций ссылок ---');
  
  const linkvertise = await readJsonFallback('linkvertise-links.json') || {};
  const lootlabs = await readJsonFallback('lootlabs-links.json') || {};
  const workink = await readJsonFallback('workink-links.json') || {};

  // Собираем все уникальные ID скриптов из всех файлов ссылок
  const allScriptIds = new Set([
    ...Object.keys(linkvertise),
    ...Object.keys(lootlabs),
    ...Object.keys(workink)
  ]);

  for (const scriptId of allScriptIds) {
    const lv = linkvertise[scriptId] || {};
    const ll = lootlabs[scriptId] || {};
    const wi = workink[scriptId] || {};

    // Собираем целевой объект конфигурации
    const targetConfig = {
      script_id: scriptId,
      workink_enabled: wi.enabled ?? false,
      workink_link_id: wi.linkId ? String(wi.linkId) : null,
      workink_url: wi.workInkUrl || null,
      lootlabs_enabled: ll.enabled ?? false,
      lootlabs_url: ll.lootLabsUrl || null,
      linkvertise_enabled: lv.enabled ?? false,
      linkvertise_url: lv.linkvertiseUrl || null
    };

    // Проверяем существующую запись в БД
    const { data: dbConfig, error } = await supabase
      .from('script_configs')
      .select('*')
      .eq('script_id', scriptId)
      .maybeSingle();

    if (error) {
      console.error(`Ошибка получения конфига для ${scriptId}:`, error.message);
      continue;
    }

    // Определяем, есть ли изменения
    let needsUpdate = false;
    if (!dbConfig) {
      needsUpdate = true;
    } else {
      const keysToCompare = [
        'workink_enabled', 'workink_link_id', 'workink_url',
        'lootlabs_enabled', 'lootlabs_url',
        'linkvertise_enabled', 'linkvertise_url'
      ];
      for (const key of keysToCompare) {
        if (dbConfig[key] !== targetConfig[key]) {
          needsUpdate = true;
          break;
        }
      }
    }

    if (needsUpdate) {
      console.log(`Обновление конфигурации для скрипта: ${scriptId}...`);
      const { error: upsertErr } = await supabase
        .from('script_configs')
        .upsert(targetConfig);

      if (upsertErr) {
        console.error(`Не удалось обновить конфиг ${scriptId}:`, upsertErr.message);
      } else {
        console.log(`Конфигурация ${scriptId} успешно синхронизирована.`);
      }
    } else {
      console.log(`Конфигурация ${scriptId} не изменилась, пропускаем.`);
    }
  }
}

async function syncKeys() {
  console.log('\n--- Синхронизация ключей ---');
  
  const localKeys = await readJsonFallback('keys.json');
  if (!localKeys || !Array.isArray(localKeys)) {
    console.log('Файл keys.json не найден или пуст. Пропуск.');
    return;
  }

  for (const key of localKeys) {
    if (!key.keyHash) {
      console.warn('Пропущен ключ без keyHash:', key);
      continue;
    }

    // Получаем текущее состояние ключа из базы данных
    const { data: dbKey, error } = await supabase
      .from('keys')
      .select('*')
      .eq('key_hash', key.keyHash)
      .maybeSingle();

    if (error) {
      console.error(`Ошибка получения ключа ${key.keyHash}:`, error.message);
      continue;
    }

    const targetKey = {
      name: key.name || null,
      key_hash: key.keyHash,
      script_id: key.scriptId,
      expires_at: key.expiresAt || null,
      disabled: key.disabled ?? false
    };

    let needsUpdate = false;
    if (!dbKey) {
      needsUpdate = true;
    } else {
      if (
        dbKey.name !== targetKey.name ||
        dbKey.script_id !== targetKey.script_id ||
        dbKey.disabled !== targetKey.disabled ||
        !isDateEqual(dbKey.expires_at, targetKey.expires_at)
      ) {
        needsUpdate = true;
      }
    }

    if (needsUpdate) {
      console.log(`Обновление ключа с хешем ${key.keyHash.substring(0, 8)}...`);
      const { error: upsertErr } = await supabase
        .from('keys')
        .upsert(targetKey);

      if (upsertErr) {
        console.error(`Не удалось обновить ключ:`, upsertErr.message);
      } else {
        console.log(`Ключ ${key.keyHash.substring(0, 8)} успешно синхронизирован.`);
      }
    } else {
      console.log(`Ключ ${key.keyHash.substring(0, 8)} не требует обновлений.`);
    }
  }
}

async function run() {
  try {
    await syncScripts();
    await syncScriptConfigs();
    await syncKeys();
    console.log('\nСинхронизация завершена успешно.');
  } catch (err) {
    console.error('Критическая ошибка синхронизации:', err);
  }
}

run();