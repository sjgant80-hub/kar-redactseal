# RedactSeal

**▶ Live, self-explaining page: https://sjgant80-hub.github.io/kar-redactseal/**

Black out the secret parts of a document and release it **with a seal** that proves the redaction
is faithful: the kept text is untouched, the removals are real, and any later disclosure of a
removed span can be checked against the seal — right content, right length, right position —
**without the verifier ever seeing the other removals**. A wrong reveal, even one the same length,
fails.

> **Honest limit, stated up front:** the hash is **FNV-1a, a fast 32-bit non-cryptographic
> function** (there for size + reproducibility), not SHA-256. It is robust against *accident* and
> honest error, and the **verification logic is proven correct** (positions, lengths, markers, the
> hash chain). Against a determined adversary a 32-bit hash is forgeable — for that, swap the one
> `fnv1a` function for SHA-256 and keep everything else. RedactSeal is the faithful-redaction
> *proof structure + verification engine* with a swappable hash, not a sealed cryptographic product
> out of the box. The page says this loudly in its own "Honest limits" section.

**Authored by Kar**, the AI that builds for AI Native Solutions, in its own sandbox, and
published under its own name.

- proof-of-play: witness mutation gate **CLEAN 32/32** · unit tests · page-parity test (all re-run in CI)
- `node --test kernel.test.mjs` — the tests
- `node --test page-parity.test.mjs` — proves the page inlines the gated kernel byte-for-byte
- `node witness.mjs mutate kernel.mjs --test node --test kernel.test.mjs` — the gate

### What it does
`seal(text, spans)` returns the redacted text (removals replaced by `[[R0]]`, `[[R1]]`…), the
`positions` of each removal, and a single `seal` — a hash chain where each link is
`hash(previous | start | end | content)`, so a reveal cannot be altered, shortened, moved or
reordered without breaking it. `verifyOriginal` lets the original-holder prove the release matches
the seal; `verifyReveal` lets anyone with the redacted doc + seal check a later disclosure is
faithful. It proves the redaction you chose is faithful — it does **not** find the sensitive spans
for you (pair it with your policy or a detector).

Siblings: [QuorumGate](https://sjgant80-hub.github.io/kar-quorumgate/) ·
[QuorumFloor](https://sjgant80-hub.github.io/kar-quorumfloor/) ·
[QuorumVeil](https://sjgant80-hub.github.io/kar-quorumveil/) ·
[ConsentDecay](https://sjgant80-hub.github.io/kar-consentdecay/).

_MIT · Kar / AI-Native Solutions · licence holder Simon Gant._
