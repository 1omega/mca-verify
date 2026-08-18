# mca-verify

Reference verifier for the **Machine Commerce Attestation (MCA) specification, draft v0.1** — the open standard for tamper-evident attestation of machine commerce: hash-chained attestation records, RFC 6962 Merkle-anchored checkpoints, Ed25519 public-log signatures (HMAC private mode), witnessing, and the Commerce Triple.

Dependency-free ESM JavaScript (Node ≥ 18, `node:crypto` only). Spec: <https://github.com/1omega/mca-spec> · Reference implementation & public verification API: <https://iondra.com>

## Usage

```sh
# Record integrity (optionally re-binding a supplied Evidence Bundle)
mca verify record <file> [--evidence f]

# Chain integrity — gapless seq, prev_hash linkage (JSONL, one record per line)
mca verify chain <jsonl>

# Checkpoint — Merkle root over the range, operator signature, checkpoint chain
mca verify checkpoint <cp> --records <jsonl> [--prev cp] [--key pem] [--hmac-secret s]

# Inclusion proof — RFC 6962 audit path against a checkpoint root
mca verify inclusion --record f --proof f --checkpoint f
```

Exit codes: `0` = VALID · `1` = INVALID · `2` = usage/IO error.

Programmatic use (ESM):

```js
import { verifyRecord, verifyChain, verifyCheckpoint, verifyInclusion } from "@mca/verify";
```

## Result vocabulary

Every check returns `{ result: "VALID" | "INVALID", reasons: string[] }` — never a bare boolean. Alongside pass/fail reasons, caveats are surfaced in `reasons` and never suppressed:

| Caveat | Meaning |
|---|---|
| `UNWITNESSED` | Checkpoint has no independent witness countersignatures |
| `UNANCHORED` | No prior checkpoint supplied and the checkpoint is not genesis-anchored |
| `SEALED_HISTORY_PRESENT` | The log sealed a damaged region (`notes.sealed_history`) — history before the seal is attested as sealed, not rewritten |
| `PRIVATE_MODE` | HMAC (`hs256`) checkpoint — non-verifiable by third parties by design (spec §7) |

## Conformance suite

`test/vectors/` is the **MCA v0.1 conformance suite**: a valid 5-record x402 commerce chain, a tampered-record chain, a sequence-gap chain, an Ed25519-signed checkpoint and a forged variant, an inclusion proof, and a matching evidence bundle. It regenerates deterministically on every run:

```sh
npm test   # node test/gen-vectors.js && node --test test/verify.test.js
```

Per spec Appendix B, an implementation claiming **Verifier** conformance MUST pass these vectors (positive chains, tampered-record, gap, forged-checkpoint, and the privacy/sealed-history cases).

## License

Apache-2.0 (this reference code). The MCA specification text is CC-BY-4.0.
