const assert = require('node:assert');
const http = require('node:http');
const { server } = require('./server.js');

function requestJson(port, path, method = 'GET', body = null) {
  return new Promise((resolve, reject) => {
    const payload = body ? Buffer.from(JSON.stringify(body), 'utf8') : null;
    const req = http.request(
      {
        hostname: '127.0.0.1',
        port,
        path,
        method,
        headers: payload
          ? { 'Content-Type': 'application/json', 'Content-Length': payload.length }
          : {}
      },
      (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => {
          try {
            resolve({
              status: res.statusCode,
              data: JSON.parse(Buffer.concat(chunks).toString('utf8'))
            });
          } catch (e) {
            reject(e);
          }
        });
      }
    );
    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}

async function runTests() {
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;

  try {
    // 1. Kiểm tra trạng thái khởi tạo
    const st = await requestJson(port, '/api/state');
    assert.strictEqual(st.status, 200);
    assert.strictEqual(st.data.ok, true);
    assert.strictEqual(st.data.activeCase.id, 'case-chimera-lab');

    // 2. Giám định vật chứng quyết định
    const ev = await requestJson(port, '/api/evidence/inspect', 'POST', {
      evidenceId: 'ev-badge-spoof'
    });
    assert.strictEqual(ev.status, 200);
    assert.strictEqual(ev.data.inspectedEvidence.inspected, true);

    // 3. Thẩm vấn và đập bằng chứng bẻ gãy ngoại phạm (Alibi Breaker)
    const inter = await requestJson(port, '/api/interrogate', 'POST', {
      suspectId: 'suspect-linh',
      tactic: 'PRESENT_EVIDENCE',
      evidenceId: 'ev-badge-spoof'
    });
    assert.strictEqual(inter.status, 200);
    assert.strictEqual(inter.data.lastEntry.alibiBroken, true);
    assert.ok(inter.data.lastEntry.bpm >= 120);

    // 4. Kết luận phá án chính xác
    const acc = await requestJson(port, '/api/accuse', 'POST', {
      suspectId: 'suspect-linh',
      evidenceId: 'ev-badge-spoof',
      notes: 'Nhân bản RFID và cài cronjob giả tạo ngoại phạm'
    });
    assert.strictEqual(acc.status, 200);
    assert.strictEqual(acc.data.verdict.solved, true);

    // 5. Sinh vụ án ngẫu nhiên (Procedural Mystery Generator)
    const gen = await requestJson(port, '/api/case/generate', 'POST', {});
    assert.strictEqual(gen.status, 200);
    assert.ok(gen.data.generatedCase.id.startsWith('case-proc-'));

    console.log('✅ Tất cả 5/5 bài kiểm thử NoirDetective đều PASS!');
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
}

runTests().catch((err) => {
  console.error('❌ Lỗi kiểm thử:', err);
  process.exit(1);
});

