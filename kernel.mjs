// RedactSeal — pure kernel: redact named spans, emit a content-addressed seal
// (a hash chain over the removed spans + their positions) so the redacted
// document can be proven faithful to the original without seeing the removals.
// Total: bad input returns {ok:false, why} — never throws.

const FNV_OFFSET = 2166136261;
const FNV_PRIME = 16777619;

function fnv1aRaw(str) {
  let h = FNV_OFFSET >>> 0;
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i);
    h = Math.imul(h, FNV_PRIME) >>> 0;
  }
  return h >>> 0;
}

export function fnv1a(str) {
  if (typeof str !== 'string') return { ok: false, why: 'input must be a string' };
  return { ok: true, hash: fnv1aRaw(str) };
}

function normalizeSpans(text, spans) {
  if (!Array.isArray(spans)) return { ok: false, why: 'spans must be an array' };
  const out = [];
  for (const s of spans) {
    if (s === null || typeof s !== 'object' || Array.isArray(s)) {
      return { ok: false, why: 'each span must be an object {start,end}' };
    }
    const { start, end } = s;
    if (!Number.isInteger(start) || !Number.isInteger(end)) {
      return { ok: false, why: 'span start/end must be integers' };
    }
    if (start < 0 || end > text.length || start >= end) {
      return { ok: false, why: `span [${start},${end}) out of range or empty` };
    }
    out.push({ start, end });
  }
  out.sort((a, b) => a.start - b.start);
  for (let i = 1; i < out.length; i++) {
    if (out[i].start < out[i - 1].end) return { ok: false, why: 'spans overlap' };
  }
  return { ok: true, spans: out };
}

// seal(text, spans) -> { ok, redacted, positions, seal, spanCount }
// positions carry {start,end,len} in the ORIGINAL text; removed content is
// replaced by [[R0]], [[R1]], ... markers in span order. The seal is a hash
// chain: link_i = fnv1a(`${chain}|${start}|${end}|${removed}`).
export function seal(text, spans) {
  if (typeof text !== 'string') return { ok: false, why: 'text must be a string' };
  const norm = normalizeSpans(text, spans);
  if (!norm.ok) return norm;
  let chain = FNV_OFFSET >>> 0;
  const positions = [];
  let redacted = '';
  let cursor = 0;
  for (let i = 0; i < norm.spans.length; i++) {
    const { start, end } = norm.spans[i];
    const removed = text.slice(start, end);
    chain = fnv1aRaw(`${chain}|${start}|${end}|${removed}`);
    positions.push({ start, end, len: end - start });
    redacted += text.slice(cursor, start) + `[[R${i}]]`;
    cursor = end;
  }
  redacted += text.slice(cursor);
  return { ok: true, redacted, positions, seal: chain, spanCount: norm.spans.length };
}

// verifyOriginal(text, spans, sealValue) -> { ok, valid }
// Holder of the ORIGINAL recomputes the chain and checks it matches the seal.
export function verifyOriginal(text, spans, sealValue) {
  if (!Number.isInteger(sealValue)) return { ok: false, why: 'seal must be an integer' };
  const sealed = seal(text, spans);
  if (!sealed.ok) return sealed;
  return { ok: true, valid: sealed.seal === (sealValue >>> 0) };
}

// verifyReveal(redacted, positions, revealed, sealValue) -> { ok, valid, original? }
// Holder of the REDACTED doc + seal checks a later disclosure: revealed[i] is
// the claimed content of positions[i]. Faithful iff every marker is present,
// every revealed span has the pinned length, the reconstructed document places
// each revealed span exactly at its claimed position, and the recomputed hash
// chain equals the seal. valid:false is a verdict, not an input error.
export function verifyReveal(redacted, positions, revealed, sealValue) {
  if (typeof redacted !== 'string') return { ok: false, why: 'redacted must be a string' };
  if (!Array.isArray(positions) || !Array.isArray(revealed)) {
    return { ok: false, why: 'positions and revealed must be arrays' };
  }
  if (positions.length !== revealed.length) {
    return { ok: false, why: 'positions/revealed length mismatch' };
  }
  if (!Number.isInteger(sealValue)) return { ok: false, why: 'seal must be an integer' };
  let chain = FNV_OFFSET >>> 0;
  let original = redacted;
  for (let i = 0; i < positions.length; i++) {
    const p = positions[i];
    if (p === null || typeof p !== 'object' || !Number.isInteger(p.start) || !Number.isInteger(p.end)) {
      return { ok: false, why: `position ${i} must be {start,end} with integers` };
    }
    const r = revealed[i];
    if (typeof r !== 'string') return { ok: false, why: `revealed[${i}] must be a string` };
    if (r.length !== p.end - p.start) {
      return { ok: true, valid: false, why: `revealed[${i}] length does not match pinned span` };
    }
    const marker = `[[R${i}]]`;
    if (!original.includes(marker)) {
      return { ok: true, valid: false, why: `marker ${marker} missing from redacted document` };
    }
    original = original.replace(marker, r);
    chain = fnv1aRaw(`${chain}|${p.start}|${p.end}|${r}`);
  }
  for (let i = 0; i < positions.length; i++) {
    if (original.slice(positions[i].start, positions[i].end) !== revealed[i]) {
      return { ok: true, valid: false, why: `revealed[${i}] does not sit at its claimed position` };
    }
  }
  if (chain !== (sealValue >>> 0)) return { ok: true, valid: false, why: 'seal mismatch' };
  return { ok: true, valid: true, original };
}
