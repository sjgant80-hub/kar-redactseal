// Guards the promise the live page makes: the kernel inlined in index.html is
// byte-for-byte the gated kernel.mjs body (minus the `export` markers). If the
// kernel changes and the page is not updated (or vice versa), this test fails
// and CI goes red.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

test('index.html inlines kernel.mjs byte-for-byte', () => {
  const kernel = readFileSync(new URL('./kernel.mjs', import.meta.url), 'utf8').replace(/\r\n/g, '\n');
  const page = readFileSync(new URL('./index.html', import.meta.url), 'utf8').replace(/\r\n/g, '\n');

  const start = kernel.indexOf('const FNV_OFFSET');
  const endMark = 'return { ok: true, valid: true, original };\n}';
  const end = kernel.indexOf(endMark, start) + endMark.length;
  const body = kernel.slice(start, end).replace(/export function/g, 'function');

  assert.ok(body.length > 2000, 'kernel body extracted');
  assert.ok(page.includes(body), 'the exact kernel.mjs source (minus `export`) must appear verbatim in index.html');
});
