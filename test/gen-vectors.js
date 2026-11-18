/**
 * Deterministically regenerates test/vectors/ — the MCA v0.1 conformance
 * suite. Run via `npm test` (always regenerates before the test run, so the
 * tests can never silently depend on stale artifacts).
 *
 * The Ed25519 keypair is generated fresh on each run; everything else is
 * fixed. Determinism of the *structure* (5-record chain, tampered/gap
 * variants, checkpoint, inclusion path, evidence bundle) is what matters —
 * tests only reference relationships the generator itself establishes.
 */

import { generateKeyPairSync, sign as cryptoSign } from "node:crypto";
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { canonicalize } from "../src/canonicalize.js";
import { hashCanonical, recordHash, checkpointHash, keyIdFromPublicKeyPem, ZERO64 } from "../src/hash.js";
import { merkleRoot, auditPath } from "../src/merkle.js";

const here = dirname(fileURLToPath(import.meta.url));
const outDir = join(here, "vectors");
mkdirSync(outDir, { recursive: true });

const LOG_ID = "log.iondra.com/main";
const BASE_TS = Date.UTC(2026, 0, 15, 12, 0, 0); // 2026-01-15T12:00:00.000Z

// ─── Evidence bundles (never sent to the log — only their hashes are) ───────
const evidenceBundles = [
  { rail_receipt: { rail: "x402", tx: "0xaaa1", amount: "1.25", currency: "USD" }, note: "weather API call" },
  { rail_receipt: { rail: "x402", tx: "0xbbb2", amount: "4.00", currency: "USD" }, note: "dataset query" },
  { rail_receipt: { rail: "x402", tx: "0xccc3", amount: "0.75", currency: "USD" }, note: "image generation" },
  { rail_receipt: { rail: "x402", tx: "0xddd4", amount: "2.50", currency: "USD" }, note: "translation batch" },
  { rail_receipt: { rail: "x402", tx: "0xeee5", amount: "9.99", currency: "USD" }, note: "market data feed" },
];

// ─── 5-record valid chain with realistic x402 commerce triples ──────────────
const chain = [];
let prev = ZERO64;
for (let i = 0; i < 5; i++) {
  const ar = {
    mca_version: "0.1",
    record_id: `018f3c2a-0000-7000-8000-00000000000${i}`,
    log_id: LOG_ID,
    seq: i,
    timestamp: new Date(BASE_TS + i * 60_000).toISOString(),
    subject_type: "machine",
    subject_id: `spiffe://acme.example/agent/procurement-${i}`,
    action: "commerce.payment.executed",
    evidence_hash: hashCanonical(evidenceBundles[i]),
    prev_hash: prev,
    commerce: {
      rail: "x402",
      request_hash: hashCanonical({ method: "GET", endpoint: `https://api.vendor${i}.example/data` }),
      payment_hash: hashCanonical(evidenceBundles[i].rail_receipt),
      delivery_hash: hashCanonical({ content: `delivered-payload-${i}` }),
      amount: { value: evidenceBundles[i].rail_receipt.amount, currency: "USD" },
      counterparty: `api.vendor${i}.example`,
    },
  };
  chain.push(ar);
  prev = recordHash(ar);
}

const writeJsonl = (name, rows) =>
  writeFileSync(join(outDir, name), rows.map((r) => JSON.stringify(r)).join("\n") + "\n");
const writeJson = (name, obj) =>
  writeFileSync(join(outDir, name), JSON.stringify(obj, null, 2) + "\n");

writeJsonl("chain-valid.jsonl", chain);

// Tampered: amount altered at seq 2 (breaks its record_hash → seq 3 link).
const tampered = chain.map((r) => JSON.parse(JSON.stringify(r)));
tampered[2].commerce.amount.value = "7500.00";
writeJsonl("chain-tampered.jsonl", tampered);

// Gap: seq 2 removed entirely.
writeJsonl("chain-gap.jsonl", chain.filter((r) => r.seq !== 2));

// ─── Checkpoint over range 0..4, Ed25519-signed ─────────────────────────────
const { publicKey, privateKey } = generateKeyPairSync("ed25519");
const pubPem = publicKey.export({ type: "spki", format: "pem" });
writeFileSync(join(outDir, "log.pub.pem"), pubPem);

const cpUnsigned = {
  mca_version: "0.1",
  log_id: LOG_ID,
  checkpoint_id: "cp-0001",
  range: { from_seq: 0, to_seq: 4 },
  merkle_root: merkleRoot(chain.map(recordHash)),
  prev_checkpoint_hash: ZERO64, // genesis checkpoint
  hash_alg: "sha-256",
  timestamp: new Date(BASE_TS + 5 * 60_000).toISOString(),
};
const sigBytes = cryptoSign(null, Buffer.from(canonicalize(cpUnsigned), "utf8"), privateKey);
const checkpoint = {
  ...cpUnsigned,
  signature: { alg: "ed25519", key_id: "log-main-2026-01", sig: sigBytes.toString("base64url") },
  witnesses: [],
};
writeJson("checkpoint-valid.json", checkpoint);

// Forged: wrong merkle_root, signature kept (covers the ORIGINAL body).
const forged = JSON.parse(JSON.stringify(checkpoint));
forged.merkle_root = merkleRoot(chain.map(recordHash)).replace(/^./, forged.merkle_root[0] === "a" ? "b" : "a");
writeJson("checkpoint-forged.json", forged);

// ─── Witnessed checkpoint (addendum 0.1.1, spec §8) ─────────────────────────
// An independent witness cosigns the SAME canonical bytes the operator signed.
const witness = generateKeyPairSync("ed25519");
const witnessPem = witness.publicKey.export({ type: "spki", format: "pem" });
writeFileSync(join(outDir, "witness.pub.pem"), witnessPem);
const witnessEntry = {
  witness_id: "witness.example.org",
  key_id: keyIdFromPublicKeyPem(witnessPem),
  alg: "ed25519",
  timestamp: new Date(BASE_TS + 6 * 60_000).toISOString(),
  sig: cryptoSign(null, Buffer.from(canonicalize(cpUnsigned), "utf8"), witness.privateKey).toString("base64url"),
};
writeJson("checkpoint-witnessed.json", { ...checkpoint, witnesses: [witnessEntry] });
// Bad witness: a cosignature that does not cover this checkpoint's bytes.
const strayCp = { ...cpUnsigned, timestamp: new Date(BASE_TS + 7 * 60_000).toISOString() };
writeJson("checkpoint-witness-forged.json", {
  ...checkpoint,
  witnesses: [{ ...witnessEntry, sig: cryptoSign(null, Buffer.from(canonicalize(strayCp), "utf8"), witness.privateKey).toString("base64url") }],
});

// ─── Inclusion proof for the seq 3 record ────────────────────────────────────
writeJson("inclusion-record.json", chain[3]);
writeJson("inclusion-path.json", auditPath(chain.map(recordHash), 3));
// The same proof in the object form a log serves (addendum 0.1.1).
writeJson("inclusion-wrapped.json", {
  checkpoint_id: checkpoint.checkpoint_id,
  record_hash: recordHash(chain[3]),
  leaf_index: 3,
  tree_size: 5,
  audit_path: auditPath(chain.map(recordHash), 3),
  merkle_root: checkpoint.merkle_root,
});
writeJson("evidence-3.json", evidenceBundles[3]);

// ─── v0.2: the checkpoint chain link (spec §6.3) ────────────────────────────
// One log, four checkpoints over the 5-record chain above, with its own keys
// so this directory stays self-consistent:
//
//   cp-1  0.1  seq 0-1  genesis
//   cp-2  0.1  seq 2    link = full form of cp-1 AS EMITTED (one witness)
//   cp-3  0.2  seq 3    link = checkpoint_hash(cp-2)      <- the transition
//   cp-4  0.2  seq 4    link = checkpoint_hash(cp-3)
//
// Each checkpoint is written "as emitted" and "as served later", after a
// second witness cosigned and the log merged the entry. expected.json states
// the result a conforming verifier reports for every (checkpoint, prev) pair.
const v02Dir = join(outDir, "v02");
mkdirSync(v02Dir, { recursive: true });
const v2Json = (name, obj) => writeFileSync(join(v02Dir, name), JSON.stringify(obj, null, 2) + "\n");
const v2Key = (name) => {
  const k = generateKeyPairSync("ed25519");
  const pem = k.publicKey.export({ type: "spki", format: "pem" });
  writeFileSync(join(v02Dir, `${name}.pub.pem`), pem);
  return { privateKey: k.privateKey, key_id: keyIdFromPublicKeyPem(pem) };
};
const v2Log = v2Key("log");
const v2WitA = { ...v2Key("witness-a"), witness_id: "witness.a.example" };
const v2WitB = { ...v2Key("witness-b"), witness_id: "witness.b.example" };
const signBody = (body, key) => cryptoSign(null, Buffer.from(canonicalize(body), "utf8"), key).toString("base64url");
const cosign = (body, w, minute) => ({
  witness_id: w.witness_id, key_id: w.key_id, alg: "ed25519",
  timestamp: new Date(BASE_TS + minute * 60_000).toISOString(), sig: signBody(body, w.privateKey),
});
function v2Checkpoint({ n, version, from, to, prev, minute, id }) {
  const body = {
    mca_version: version, log_id: LOG_ID, checkpoint_id: id ?? `t-cp-${n}`,
    range: { from_seq: from, to_seq: to }, merkle_root: merkleRoot(chain.slice(from, to + 1).map(recordHash)),
    prev_checkpoint_hash: prev, hash_alg: "sha-256", timestamp: new Date(BASE_TS + minute * 60_000).toISOString(),
  };
  const signed = { ...body, signature: { alg: "ed25519", key_id: v2Log.key_id, sig: signBody(body, v2Log.privateKey) } };
  const a = cosign(body, v2WitA, minute + 1);
  const b = cosign(body, v2WitB, minute + 30); // arrives late
  return { emitted: { ...signed, witnesses: [a] }, served: { ...signed, witnesses: [a, b] }, signed, a, b };
}
[[1, 0, 1], [2, 2, 2], [3, 3, 3], [4, 4, 4]].forEach(([n, from, to]) =>
  writeFileSync(join(v02Dir, `records-cp-${n}.jsonl`), chain.slice(from, to + 1).map((r) => JSON.stringify(r)).join("\n") + "\n"));

const t1 = v2Checkpoint({ n: 1, version: "0.1", from: 0, to: 1, prev: ZERO64, minute: 10 });
const t2 = v2Checkpoint({ n: 2, version: "0.1", from: 2, to: 2, prev: hashCanonical(t1.emitted), minute: 20 });
const t3 = v2Checkpoint({ n: 3, version: "0.2", from: 3, to: 3, prev: checkpointHash(t2.emitted), minute: 80 });
const t4 = v2Checkpoint({ n: 4, version: "0.2", from: 4, to: 4, prev: checkpointHash(t3.emitted), minute: 140 });
for (const [n, t] of [[1, t1], [2, t2], [3, t3], [4, t4]]) {
  v2Json(`cp-${n}.emitted.json`, t.emitted);
  v2Json(`cp-${n}.served.json`, t.served);
}
// A copy of cp-1 taken before witness A's entry was merged: fewer entries than the 0.1 link covers.
v2Json("cp-1.cached-early.json", { ...t1.signed, witnesses: [] });
// Other copies of cp-3 a verifier may hold: none of them changes its checkpoint_hash.
v2Json("cp-3.no-witnesses-member.json", t3.signed);
v2Json("cp-3.empty-witnesses.json", { ...t3.signed, witnesses: [] });
v2Json("cp-3.reordered.json", { ...t3.signed, witnesses: [t3.b, t3.a] });
// Copies that are NOT cp-3: a changed body (new `notes`), signature left as it was.
v2Json("cp-3.altered-body.json", { ...t3.emitted, notes: { sealed_history: true } });
// Operator mistakes, each correctly signed by the log key.
v2Json("cp-4.full-form-link.json", v2Checkpoint({ n: 4, version: "0.2", from: 4, to: 4, prev: hashCanonical(t3.emitted), minute: 140 }).emitted);
v2Json("cp-4.downgrade.json", v2Checkpoint({ n: 4, version: "0.1", from: 4, to: 4, prev: hashCanonical(t3.emitted), minute: 140 }).emitted);
v2Json("cp-2.signed-body-link.json", v2Checkpoint({ n: 2, version: "0.1", from: 2, to: 2, prev: checkpointHash(t1.emitted), minute: 20 }).emitted);
// A checkpoint of another log offered as the previous one.
const otherLog = { ...t3.signed, log_id: `${LOG_ID}/other`, witnesses: [] };
v2Json("cp-3.other-log.json", otherLog);
v2Json("cp-4.links-other-log.json", v2Checkpoint({ n: 4, version: "0.2", from: 4, to: 4, prev: checkpointHash(otherLog), minute: 140 }).emitted);

const A = `WITNESSED:${v2WitA.witness_id}`, B = `WITNESSED:${v2WitB.witness_id}`;
const LATE = `PREV_WITNESS_ADDED_AFTER_LINK:${v2WitB.witness_id}`;
const BROKEN = "checkpoint-chain-broken:prev_checkpoint_hash-mismatch";
v2Json("expected.json", {
  about: "MCA v0.2 checkpoint-link vectors. For each case: verify `cp` with `records`, the log key, both witness keys and `prev` (when given). `reasons` is the exact list, in order.",
  checkpoint_hash: { "t-cp-1": checkpointHash(t1.emitted), "t-cp-2": checkpointHash(t2.emitted), "t-cp-3": checkpointHash(t3.emitted), "t-cp-4": checkpointHash(t4.emitted) },
  cases: [
    { name: "0.1 genesis", cp: "cp-1.emitted.json", records: "records-cp-1.jsonl", result: "VALID", reasons: [A] },
    { name: "0.1 link, previous checkpoint as it was when the link was made", cp: "cp-2.emitted.json", prev: "cp-1.emitted.json", records: "records-cp-2.jsonl", result: "VALID", reasons: [A] },
    { name: "0.1 link, a witness was merged into the previous checkpoint afterwards", cp: "cp-2.emitted.json", prev: "cp-1.served.json", records: "records-cp-2.jsonl", result: "VALID", reasons: [LATE, A] },
    { name: "0.1 link, cached previous checkpoint that lacks a witness entry the link covered", cp: "cp-2.emitted.json", prev: "cp-1.cached-early.json", records: "records-cp-2.jsonl", result: "INVALID", reasons: [BROKEN],
      note: "A 0.1 link cannot be checked from a copy taken before the covered witness entry was merged. Fetch the served copy, confirm it has the same checkpoint_hash as the cached one, and verify against that." },
    { name: "0.1 checkpoint that uses the 0.2 form", cp: "cp-2.signed-body-link.json", prev: "cp-1.emitted.json", records: "records-cp-2.jsonl", result: "INVALID", reasons: ["checkpoint-chain-broken:link-is-the-0.2-signed-body-form-in-a-0.1-checkpoint"] },
    { name: "transition: first 0.2 checkpoint links to the last 0.1 checkpoint, as emitted", cp: "cp-3.emitted.json", prev: "cp-2.emitted.json", records: "records-cp-3.jsonl", result: "VALID", reasons: [A] },
    { name: "transition: the same, previous checkpoint as served later with a late witness", cp: "cp-3.served.json", prev: "cp-2.served.json", records: "records-cp-3.jsonl", result: "VALID", reasons: [A, B] },
    { name: "0.2 link, previous checkpoint as emitted", cp: "cp-4.emitted.json", prev: "cp-3.emitted.json", records: "records-cp-4.jsonl", result: "VALID", reasons: [A] },
    { name: "0.2 link, previous checkpoint with a late witness", cp: "cp-4.emitted.json", prev: "cp-3.served.json", records: "records-cp-4.jsonl", result: "VALID", reasons: [A] },
    { name: "0.2 link, cached previous checkpoint with no witnesses member", cp: "cp-4.emitted.json", prev: "cp-3.no-witnesses-member.json", records: "records-cp-4.jsonl", result: "VALID", reasons: [A] },
    { name: "0.2 link, previous checkpoint with an empty witnesses array", cp: "cp-4.emitted.json", prev: "cp-3.empty-witnesses.json", records: "records-cp-4.jsonl", result: "VALID", reasons: [A] },
    { name: "0.2 link, previous checkpoint with witnesses in another order", cp: "cp-4.emitted.json", prev: "cp-3.reordered.json", records: "records-cp-4.jsonl", result: "VALID", reasons: [A] },
    { name: "0.2 link, previous checkpoint body altered", cp: "cp-4.emitted.json", prev: "cp-3.altered-body.json", records: "records-cp-4.jsonl", result: "INVALID", reasons: [BROKEN] },
    { name: "0.2 link, wrong previous checkpoint", cp: "cp-4.emitted.json", prev: "cp-2.emitted.json", records: "records-cp-4.jsonl", result: "INVALID", reasons: [BROKEN] },
    { name: "0.2 checkpoint that uses the 0.1 full form", cp: "cp-4.full-form-link.json", prev: "cp-3.emitted.json", records: "records-cp-4.jsonl", result: "INVALID", reasons: ["checkpoint-chain-broken:link-is-the-0.1-full-form-in-a-0.2-checkpoint"] },
    { name: "0.1 checkpoint after a 0.2 checkpoint", cp: "cp-4.downgrade.json", prev: "cp-3.emitted.json", records: "records-cp-4.jsonl", result: "INVALID", reasons: ["checkpoint-chain-broken:version-downgrade:0.1-after-0.2"] },
    { name: "previous checkpoint from another log", cp: "cp-4.links-other-log.json", prev: "cp-3.other-log.json", records: "records-cp-4.jsonl", result: "INVALID", reasons: ["checkpoint-chain-broken:prev-checkpoint-is-from-another-log"] },
  ],
});

console.log(`gen-vectors: wrote 13 files to ${outDir} and the v0.2 set to ${v02Dir}`);
