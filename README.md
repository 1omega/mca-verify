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

# checkpoint_hash (0.2) — the hash of the bytes the operator signed. Every copy of one
# checkpoint prints the same value, whatever witness entries the copy carries
mca checkpoint-hash <cp>
```

Exit codes for `mca verify`: `0` = VALID · `1` = INVALID · `2` = usage/IO error. `mca checkpoint-hash` exits `0` when it printed a hash and `2` otherwise; it hashes without verifying, so `0` there says nothing about validity.

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
| `PREV_WITNESS_ADDED_AFTER_LINK:<witness_id>` | A v0.1 chain link reproduces only once this witness entry of the previous checkpoint is set aside: the link does not cover it. The usual cause is that the entry was merged after the link was made, but the match does not prove when it was merged. The previous checkpoint's signed content is what the link committed to |
| `UNANCHORED` | No prior checkpoint supplied and the checkpoint is not genesis-anchored |
| `SEALED_HISTORY_PRESENT` | The log sealed a damaged region (`notes.sealed_history`) — history before the seal is attested as sealed, not rewritten |
| `PRIVATE_MODE` | HMAC (`hs256`) checkpoint — non-verifiable by third parties by design (spec §7) |

## Conformance suite

`test/vectors/` is the **MCA v0.1 conformance suite**: a valid 5-record x402 commerce chain, a tampered-record chain, a sequence-gap chain, an Ed25519-signed checkpoint and a forged variant, an inclusion proof, and a matching evidence bundle. The vectors are checked in and `npm test` runs against them as they are:

```sh
npm test              # node --test test/verify.test.js
npm run gen-vectors   # regenerates the generated vectors with fresh keys; every signature and derived hash changes
npm run test:regen    # regenerate, then test: use after changing test/gen-vectors.js
```

Per spec Appendix B, an implementation claiming **Verifier** conformance MUST pass these vectors (positive chains, tampered-record, gap, forged-checkpoint, and the privacy/sealed-history cases).

## Verifying the live IONDRA log

`test/vectors/production/` holds checkpoints `rh1-cp-5..8`, records `seq 0..5`, the operator key and one served inclusion proof, captured from `log.iondra.com/main/record-hash-v1` on 2026-11-04, and checkpoints `rh1-cp-9..15` with their records and both witness keys, captured on 2026-11-18. They are static (not regenerated) and are the first conformance vectors taken from a running log rather than generated here:

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

## Changes in 0.2.0 (draft, not released) — the checkpoint chain link

Fixes [mca-spec issue #2](https://github.com/1omega/mca-spec/issues/2). In v0.1 `prev_checkpoint_hash` covered the whole previous checkpoint, its `witnesses` array included. Witness entries are merged after a checkpoint is emitted, so the link value depended on when the previous checkpoint was fetched.

- **`checkpoint_hash`** (`checkpointHash(cp)`, CLI `mca checkpoint-hash`): SHA-256 over the canonical checkpoint body, which is the checkpoint without its top-level `signature` and `witnesses` members. These are the bytes the operator signs and witnesses cosign. Adding, removing or reordering witness entries does not change it.
- **The link form is selected by the linking checkpoint's own `mca_version`.** A `"0.1"` checkpoint links in the v0.1 full form. A `"0.2"` checkpoint links by `checkpoint_hash`. A log may switch in place: the first `"0.2"` checkpoint links to the last `"0.1"` one by its `checkpoint_hash`. A `"0.1"` checkpoint after a `"0.2"` one is INVALID.
- **Late witnesses on v0.1 links.** When a v0.1 link does not match the previous checkpoint as supplied, the verifier checks whether it matches once some witness entries are set aside. If so the result is VALID with one `PREV_WITNESS_ADDED_AFTER_LINK:<witness_id>` caveat per entry set aside. The match still covers the previous checkpoint's whole body and operator signature. It shows that the link does not cover those entries, not when they were merged. The search is bounded: every ordered subset is tried up to 12 entries, only leading runs up to 64, and nothing beyond that. When the bound stops the search, a mismatch is reported as `checkpoint-chain-broken:prev_checkpoint_hash-mismatch:witness-search-incomplete:<n>-entries`; check that link against the previous checkpoint exactly as it stood when the link was made.
- **Cached copies.** A v0.1 link cannot be checked from a copy of the previous checkpoint taken before a covered witness entry was merged. Fetch the served copy, confirm with `mca checkpoint-hash` that it is the same checkpoint as the cached one, and verify against it. v0.2 links need none of this.
- New reasons: `checkpoint-chain-broken:link-is-the-0.1-full-form-in-a-0.2-checkpoint`, `…:link-is-the-0.2-signed-body-form-in-a-0.1-checkpoint`, `…:version-downgrade:0.1-after-0.2`, `…:prev-checkpoint-is-from-another-log`.
- New vectors: `test/vectors/v02/` (a four-checkpoint log that crosses the transition, each checkpoint as emitted and as served later, with `expected.json`), and production checkpoints `rh1-cp-9..15` with both witness keys, captured 2026-11-18.
- **Compatibility.** On the production chain `rh1-cp-5..15`, and on every v0.1 vector in this repository, the result and reasons are identical to 0.1.1. Three kinds of input change: a v0.1 link that reproduces once late witness entries are set aside is now VALID with the caveat (0.1.1: broken chain); a previous checkpoint from another log is now INVALID even if its hash matches the link (0.1.1 did not look at its `log_id`); and a record or checkpoint with no canonical form is reported as INVALID or as an input error instead of an uncaught exception.
- `npm test` no longer regenerates the vectors, so it checks the checked-in bytes and leaves the worktree clean; `npm run gen-vectors` and `npm run test:regen` regenerate.

## Changes in 0.1.1 (spec addendum 0.1.1)

- `verifyInclusion` accepts the inclusion-proof **object** a log serves (`{checkpoint_id, record_hash, leaf_index, tree_size, audit_path, merkle_root}`) as well as the bare `audit_path` array, and cross-checks `merkle_root`, `checkpoint_id` and `record_hash` against the supplied checkpoint and record.
- `verifyCheckpoint` verifies witness countersignatures when witness public keys are supplied (`opts.witnessKeys`, CLI `--witness-key`). New caveats `WITNESSED:<id>` and `WITNESS_UNVERIFIED:<id>`; a supplied key that fails to verify an entry makes the checkpoint INVALID (`bad-witness-signature:<id>`). `UNWITNESSED` now means exactly "empty `witnesses` array".
- New `verifyWitness(cp, entry, pem)` and `keyIdFromPublicKeyPem(pem)` (`"ed25519:" + first 16 hex of sha256(SPKI DER)`, the derivation the IONDRA log uses).
- New vectors: `checkpoint-witnessed.json`, `checkpoint-witness-forged.json`, `witness.pub.pem`, `inclusion-wrapped.json`, and the static `production/` set.
- No existing behaviour changes: every 0.1.0 invocation produces the same result.

## License

Apache-2.0 (this reference code). The MCA specification text is CC-BY-4.0.
