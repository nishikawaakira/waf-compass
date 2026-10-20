import test from 'node:test';
import assert from 'node:assert/strict';
import { validateInput, jstDay, handler } from './index.js';
import { createServer } from 'node:http';

const good = {
  kind: 'aws_waf', language: 'ja', snapshot: JSON.stringify({ WebACL: { Name: 'sample', Rules: [] } }),
  attack_categories: ['sqli', 'xss'], turnstile_token: 'test-token', terms_accepted: true,
};
test('accepts bounded AWS WAF input and both languages', () => {
  assert.equal(validateInput(good).kind, 'aws_waf');
  assert.equal(validateInput({ ...good, language: 'en' }).language, 'en');
});
test('rejects oversized, duplicate, and malformed requests', () => {
  assert.throws(() => validateInput({ ...good, snapshot: 'x'.repeat(1048577) }), /1 MiB/);
  assert.throws(() => validateInput({ ...good, attack_categories: ['sqli', 'sqli'] }), /categories/);
  assert.throws(() => validateInput({ ...good, snapshot: '{}' }), /GetWebACL/);
  assert.throws(() => validateInput({ ...good, turnstile_token: '' }), /Bot/);
  assert.throws(() => validateInput({ ...good, terms_accepted: false }), /Terms/);
});
test('JST day is ISO shaped', () => assert.match(jstDay(), /^\d{4}-\d{2}-\d{2}$/));
test('traffic-log format is selected and checked before submission', () => {
  const snapshot = '#Version: 1.0\n#Fields: date time c-ip cs-uri-stem cs-uri-query sc-status\n2026-10-20\t01:02:03\t192.0.2.1\t/search\t-\t200\n';
  const log = { ...good, kind: 'traffic_log', log_format: 'cloudfront', snapshot, attack_categories: [] };
  assert.equal(validateInput(log).log_format, 'cloudfront');
  assert.throws(() => validateInput({ ...log, log_format: 'alb' }), /ログフォーマットが違います/);
  assert.throws(() => validateInput({ ...log, snapshot: snapshot.replace('\t200', '\tbad') }), /ログフォーマットが違います/);
  assert.throws(() => validateInput({ ...log, attack_categories: ['sqli'] }), /categories/);
  const alb = 'https 2026-10-20T01:02:03.000000Z app/test/1 192.0.2.2:1234 10.0.0.1:443 0.001 0.001 0.001 200 200 100 200 "GET https://example.com/ HTTP/1.1" "agent"';
  assert.equal(validateInput({ ...log, log_format: 'alb', snapshot: alb }).log_format, 'alb');
  const combined = '192.0.2.3 - - [20/Oct/2026:10:02:03 +0900] "GET / HTTP/1.1" 200 123 "-" "agent"';
  assert.equal(validateInput({ ...log, log_format: 'combined', snapshot: combined }).log_format, 'combined');
  assert.throws(() => validateInput({ ...log, log_format: 'cloudfront', snapshot: combined }), /ログフォーマットが違います/);
});
test('anonymous API does not accept evaluations', async () => {
  const server = createServer(handler);
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  try {
    const base = `http://127.0.0.1:${server.address().port}`;
    const response = await fetch(`${base}/api/evaluations`, { method: 'POST', body: JSON.stringify(good), headers: { 'content-type': 'application/json' } });
    assert.equal(response.status, 401);
    const me = await fetch(`${base}/api/me`);
    assert.deepEqual(await me.json(), { authenticated: false, user: null });
    const page = await fetch(base);
    assert.equal(page.status, 200);
    const home = await page.text();
    assert.match(home, /WAF Compass/);
    assert.match(home, /href="\/favicon\.svg"/);
    const icon = await fetch(`${base}/favicon.svg`);
    assert.equal(icon.status, 200);
    assert.match(icon.headers.get('content-type'), /image\/svg\+xml/);
    assert.match(await icon.text(), /<svg/);
    assert.match(home, /href="\/terms"/);
    assert.match(home, /href="\/privacy"/);
    for (const [path, expected] of [['/terms', '利用規約'], ['/privacy', 'プライバシーポリシー']]) {
      const legalPage = await fetch(`${base}${path}`);
      assert.equal(legalPage.status, 200);
      assert.match(legalPage.headers.get('content-type'), /text\/html/);
      assert.match(await legalPage.text(), new RegExp(expected));
    }
  } finally { await new Promise(resolve => server.close(resolve)); }
});
