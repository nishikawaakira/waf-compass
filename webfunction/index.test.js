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
