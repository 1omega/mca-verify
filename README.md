# mca-verify

Reference verifier for the **Machine Commerce Attestation (MCA) specification, draft v0.1** — the open standard for tamper-evident attestation of machine commerce: hash-chained attestation records, RFC 6962 Merkle-anchored checkpoints, Ed25519 public-log signatures (HMAC private mode), witnessing, and the Commerce Triple.

Dependency-free ESM JavaScript (Node ≥ 18, `node:crypto` only). Spec: <https://github.com/1omega/mca-spec> · Reference implementation & public verification API: <https://iondra.com>

## Usage

```sh
# Record integrity (optionally re-binding a supplied Evidence Bundle)
mca verify record <file> [--evidence f]

# Chain integrity — gapless seq, prev_hash linkage (JSONL, one record per line)
mca verify chain <jsonl>

# Checkpoint — Merkle root over the range, operator signature, checkpoint chain,
# and (0.1.1) witness countersignatures when their public keys are supplied
mca verify checkpoint <cp> --records <jsonl> [--prev cp] [--key pem] [--hmac-secret s] \
                     [--witness-key <key_id|witness_id>=<pem> ...]

# Inclusion proof — RFC 6962 audit path against a checkpoint root.
# --proof is either the bare audit_path array or the inclusion-proof object a log serves (0.1.1)
mca verify inclusion --record f --proof f --checkpoint f
```

Exit codes: `0` = VALID · `1` = INVALID · `2` = usage/IO error.

Programmatic use (ESM):

```js
import { verifyRecord, verifyChain, verifyCheckpoint, verifyInclusion, verifyWitness } from "@mca/verify";
// verifyCheckpoint(cp, records, prevCp, operatorPem, hmacSecret, { witnessKeys: { "<key_id>": pem } })
```

## Result vocabulary

Every check returns `{ result: "VALID" | "INVALID", reasons: string[] }` — never a bare boolean. Alongside pass/fail reasons, caveats are surfaced in `reasons` and never suppressed:

| Caveat | Meaning |
|---|---|
| `UNWITNESSED` | Checkpoint's `witnesses` array is empty |
| `WITNESSED:<witness_id>` | A witness countersignature verified against a supplied witness public key (`--witness-key`) |
| `WITNESS_UNVERIFIED:<witness_id>` | A witness entry is present but no key for it was supplied; it was not checked |
| `UNANCHORED` | No prior checkpoint supplied and the checkpoint is not genesis-anchored |
| `SEALED_HISTORY_PRESENT` | The log sealed a damaged region (`notes.sealed_history`) — history before the seal is attested as sealed, not rewritten |
| `PRIVATE_MODE` | HMAC (`hs256`) checkpoint — non-verifiable by third parties by design (spec §7) |

## Conformance suite

`test/vectors/` is the **MCA v0.1 conformance suite**: a valid 5-record x402 commerce chain, a tampered-record chain, a sequence-gap chain, an Ed25519-signed checkpoint and a forged variant, an inclusion proof, and a matching evidence bundle. It regenerates deterministically on every run:

```sh
npm test   # node test/gen-vectors.js && node --test test/verify.test.js
```

Per spec Appendix B, an implementation claiming **Verifier** conformance MUST pass these vectors (positive chains, tampered-record, gap, forged-checkpoint, and the privacy/sealed-history cases).

## Verifying the live IONDRA log

`test/vectors/production/` holds checkpoints `rh1-cp-5..8`, records `seq 0..5`, the operator key and one served inclusion proof, captured from `log.iondra.com/main/record-hash-v1` on 2026-11-04. They are static (not regenerated) and are the first conformance vectors taken from a running log rather than generated here:

```sh
mca verify chain      test/vectors/production/chain-seq-0-5.jsonl
mca verify checkpoint test/vectors/production/checkpoint-rh1-cp-8.json \
    --records test/vectors/production/records-rh1-cp-8.jsonl \
    --prev    test/vectors/production/checkpoint-rh1-cp-7.json \
    --key     test/vectors/production/log.pub.pem
mca verify inclusion  --record test/vectors/production/record-seq-4.json \
    --proof test/vectors/production/inclusion-seq-4-wrapped.json \
    --checkpoint test/vectors/production/checkpoint-rh1-cp-8.json
```

## Changes in 0.1.1 (spec addendum 0.1.1)

- `verifyInclusion` accepts the inclusion-proof **object** a log serves (`{checkpoint_id, record_hash, leaf_index, tree_size, audit_path, merkle_root}`) as well as the bare `audit_path` array, and cross-checks `merkle_root`, `checkpoint_id` and `record_hash` against the supplied checkpoint and record.
- `verifyCheckpoint` verifies witness countersignatures when witness public keys are supplied (`opts.witnessKeys`, CLI `--witness-key`). New caveats `WITNESSED:<id>` and `WITNESS_UNVERIFIED:<id>`; a supplied key that fails to verify an entry makes the checkpoint INVALID (`bad-witness-signature:<id>`). `UNWITNESSED` now means exactly "empty `witnesses` array".
- New `verifyWitness(cp, entry, pem)` and `keyIdFromPublicKeyPem(pem)` (`"ed25519:" + first 16 hex of sha256(SPKI DER)`, the derivation the IONDRA log uses).
- New vectors: `checkpoint-witnessed.json`, `checkpoint-witness-forged.json`, `witness.pub.pem`, `inclusion-wrapped.json`, and the static `production/` set.
- No existing behaviour changes: every 0.1.0 invocation produces the same result.

## License

Apache-2.0 (this reference code). The MCA specification text is CC-BY-4.0.
