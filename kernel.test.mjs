import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as K from './kernel.mjs';

const TEXT = 'Alice met Bob at 555-1234 after the hearing.';
const SPANS = [{ start: 0, end: 5 }, { start: 10, end: 13 }, { start: 17, end: 25 }];

test('fnv1a is pinned and total', () => {
  assert.equal(K.fnv1a('hello').hash, 1335831723);
  assert.equal(K.fnv1a('').hash, 2166136261);
  assert.equal(K.fnv1a(42).ok, false);
});

test('seal pins the redacted doc, positions and chain value', () => {
  const s = K.seal(TEXT, SPANS);
  assert.equal(s.ok, true);
  assert.equal(s.redacted, '[[R0]] met [[R1]] at [[R2]] after the hearing.');
  assert.equal(s.seal, 1841016646);
  assert.equal(s.spanCount, 3);
  assert.deepEqual(s.positions[2], { start: 17, end: 25, len: 8 });
});

test('seal is deterministic and order-insensitive in span input', () => {
  const a = K.seal(TEXT, SPANS);
  const b = K.seal(TEXT, [SPANS[2], SPANS[0], SPANS[1]]);
  assert.equal(a.seal, 1841016646);
  assert.equal(b.seal, 1841016646);
});

// Kills line 34 (end > text.length → >=): a span ending exactly at
// text.length is LEGAL and must seal — the mutant refuses it.
test('span ending exactly at text.length is accepted, pinned', () => {
  const s = K.seal(TEXT, [{ start: 36, end: 44 }]);
  assert.equal(s.ok, true);
  assert.equal(s.redacted, 'Alice met Bob at 555-1234 after the [[R0]]');
  assert.equal(s.seal, 2538826584);
  assert.deepEqual(s.positions[0], { start: 36, end: 44, len: 8 });
});

// Kills line 41 (< → <=): touching spans (start === previous end) do NOT
// overlap and must seal — the mutant calls adjacency an overlap.
test('adjacent spans (start === previous end) are legal, pinned', () => {
  const s = K.seal(TEXT, [{ start: 0, end: 5 }, { start: 5, end: 10 }]);
  assert.equal(s.ok, true);
  assert.equal(s.redacted, '[[R0]][[R1]]Bob at 555-1234 after the hearing.');
  assert.equal(s.seal, 2708981105);
  assert.equal(s.spanCount, 2);
});

// Kills both line 27 mutants (|| → &&): each disjunct must refuse ALONE,
// with the exact why pinned. null throws on destructure if it leaks past;
// a primitive or an array leaks to the integer check and changes the why.
test('span type check: each bad shape refused alone, why pinned', () => {
  const nul = K.seal(TEXT, [null]);
  assert.equal(nul.ok, false);
  assert.equal(nul.why, 'each span must be an object {start,end}');
  const prim = K.seal(TEXT, [5]);
  assert.equal(prim.ok, false);
  assert.equal(prim.why, 'each span must be an object {start,end}');
  const arr = K.seal(TEXT, [[0, 5]]);
  assert.equal(arr.ok, false);
  assert.equal(arr.why, 'each span must be an object {start,end}');
});

// Kills line 31 (|| → &&): ONE non-integer bound must refuse — the mutant
// only refuses when both are non-integers.
test('one-sided non-integer span bounds refused, why pinned', () => {
  const badEnd = K.seal(TEXT, [{ start: 0, end: 2.5 }]);
  assert.equal(badEnd.ok, false);
  assert.equal(badEnd.why, 'span start/end must be integers');
  const badStart = K.seal(TEXT, [{ start: 0.5, end: 5 }]);
  assert.equal(badStart.ok, false);
  assert.equal(badStart.why, 'span start/end must be integers');
});

// Kills line 87 (|| → &&): each array check must refuse ALONE with the exact
// why — the mutant lets one-sided bad input fall through to the length check,
// which changes the why.
test('verifyReveal array check: each side refused alone, why pinned', () => {
  const badPos = K.verifyReveal('x', 'nope', [], 0);
  assert.equal(badPos.ok, false);
  assert.equal(badPos.why, 'positions and revealed must be arrays');
  const badRev = K.verifyReveal('x', [], 'nope', 0);
  assert.equal(badRev.ok, false);
  assert.equal(badRev.why, 'positions and revealed must be arrays');
});

// Kills both line 98 mutants (|| → &&): each disjunct alone must produce the
// input error {ok:false}, never a valid:false verdict or a throw.
test('verifyReveal position check: each bad shape is an input error, why pinned', () => {
  // null position — mutant on the first || dereferences null.start and throws
  const nul = K.verifyReveal('[[R0]]', [null], ['x'], 0);
  assert.equal(nul.ok, false);
  assert.equal(nul.why, 'position 0 must be {start,end} with integers');
  // non-object carrying integer start/end — mutant on the typeof || lets it
  // through to a valid:false verdict instead of an input error
  const fn = () => {};
  fn.start = 17;
  fn.end = 25;
  const nonObj = K.verifyReveal('x [[R0]] y', [fn], ['12345678'], 0);
  assert.equal(nonObj.ok, false);
  assert.equal(nonObj.why, 'position 0 must be {start,end} with integers');
  // one-sided non-integer bounds — mutant on the isInteger || needs both bad
  const fracStart = K.verifyReveal('[[R0]]', [{ start: 0.5, end: 8 }], ['1234567'], 0);
  assert.equal(fracStart.ok, false);
  assert.equal(fracStart.why, 'position 0 must be {start,end} with integers');
  const fracEnd = K.verifyReveal('[[R0]]', [{ start: 0, end: 8.5 }], ['12345678'], 0);
  assert.equal(fracEnd.ok, false);
  assert.equal(fracEnd.why, 'position 0 must be {start,end} with integers');
});

test('verifyOriginal and verifyReveal confirm a faithful redaction', () => {
  const s = K.seal(TEXT, SPANS);
  assert.equal(K.verifyOriginal(TEXT, SPANS, s.seal).valid, true);
  const vr = K.verifyReveal(s.redacted, s.positions, ['Alice', 'Bob', '555-1234'], s.seal);
  assert.equal(vr.valid, true);
  assert.equal(vr.original, TEXT);
  assert.equal(vr.original.length, 44);
});

test('tampered reveals and tampered seals are caught, not thrown', () => {
  const s = K.seal(TEXT, SPANS);
  assert.equal(K.verifyReveal(s.redacted, s.positions, ['Aline', 'Bob', '555-1234'], s.seal).valid, false);
  assert.equal(K.verifyReveal(s.redacted, s.positions, ['Al', 'Bob', '555-1234'], s.seal).valid, false);
  assert.equal(K.verifyOriginal(TEXT, SPANS, 12345).valid, false);
  assert.equal(K.verifyReveal(s.redacted, s.positions, ['Alice', 'Bob'], s.seal).ok, false);
});

test('bad input returns {ok:false, why}, never throws', () => {
  assert.equal(K.seal(null, SPANS).ok, false);
  assert.equal(K.seal(TEXT, [{ start: 0, end: 5 }, { start: 3, end: 8 }]).why, 'spans overlap');
  assert.equal(K.seal(TEXT, [{ start: 5, end: 5 }]).ok, false);
  assert.equal(K.seal(TEXT, [{ start: -1, end: 4 }]).ok, false);
  assert.equal(K.seal(TEXT, 'nope').ok, false);
  assert.equal(K.verifyReveal(7, [], [], 0).ok, false);
});
