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
import { hashCanonical, recordHash, keyIdFromPublicKeyPem, ZERO64 } from "../src/hash.js";
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

console.log(`gen-vectors: wrote 13 files to ${outDir}`);
