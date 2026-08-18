/**
 * MCA verification procedures — spec Section 13.
 *
 * Every check returns { result: "VALID" | "INVALID", reasons: string[] }.
 * Caveats (UNWITNESSED, UNANCHORED, SEALED_HISTORY_PRESENT, PRIVATE_MODE) are
 * surfaced in `reasons` alongside a VALID result and MUST NOT be suppressed
 * (spec §13 output vocabulary).
 */

import { createHmac, verify as cryptoVerify, timingSafeEqual } from "node:crypto";
import { canonicalize } from "./canonicalize.js";
import { recordHash, hashCanonical, ZERO64 } from "./hash.js";
import { merkleRoot, verifyInclusionPath } from "./merkle.js";

const HEX64 = /^[0-9a-f]{64}$/;
const SUBJECT_TYPES = new Set(["machine", "human", "system"]);

const REQUIRED_RECORD_FIELDS = [
  "mca_version",
  "record_id",
  "log_id",
  "seq",
  "timestamp",
  "subject_type",
  "subject_id",
  "action",
  "evidence_hash",
  "prev_hash",
];

const ok = (reasons = []) => ({ result: "VALID", reasons });
const bad = (reasons) => ({ result: "INVALID", reasons });

function validateRecordShape(ar, reasons) {
  for (const f of REQUIRED_RECORD_FIELDS) {
    if (ar[f] === undefined || ar[f] === null) reasons.push(`missing-field:${f}`);
  }
  if (reasons.length > 0) return;
  if (ar.mca_version !== "0.1") reasons.push(`unsupported-version:${ar.mca_version}`);
  if (typeof ar.record_id !== "string" || ar.record_id.length === 0 || ar.record_id.length > 128)
    reasons.push("bad-record_id");
  if (typeof ar.log_id !== "string" || ar.log_id.length === 0) reasons.push("bad-log_id");
  if (!Number.isInteger(ar.seq) || ar.seq < 0) reasons.push("bad-seq");
  if (!SUBJECT_TYPES.has(ar.subject_type)) reasons.push(`bad-subject_type:${ar.subject_type}`);
  if (typeof ar.subject_id !== "string" || ar.subject_id.length === 0) reasons.push("bad-subject_id");
  if (typeof ar.action !== "string" || ar.action.length === 0) reasons.push("bad-action");
  if (!HEX64.test(ar.evidence_hash)) reasons.push("bad-evidence_hash:not-64-lower-hex");
  if (!HEX64.test(ar.prev_hash)) reasons.push("bad-prev_hash:not-64-lower-hex");
  if (ar.seq === 0 && HEX64.test(ar.prev_hash) && ar.prev_hash !== ZERO64)
    reasons.push("genesis-prev_hash-not-zero");
}

/**
 * §13.1 Record integrity: canonicalize AR → record_hash; recompute
 * evidence_hash if the Evidence Bundle is supplied.
 */
export function verifyRecord(ar, evidenceBundle) {
  if (typeof ar !== "object" || ar === null || Array.isArray(ar))
    return bad(["not-a-json-object"]);
  const reasons = [];
  validateRecordShape(ar, reasons);
  if (reasons.length > 0) return bad(reasons);

  // Canonical re-serialization must succeed and reproduce a well-formed hash.
  let hash;
  try {
    hash = recordHash(ar);
  } catch (e) {
    return bad([`not-canonicalizable:${e.message}`]);
  }
  if (!HEX64.test(hash)) return bad(["record_hash-recompute-failed"]);

  if (evidenceBundle !== undefined) {
    let eh;
    try {
      eh = hashCanonical(evidenceBundle);
    } catch (e) {
      return bad([`evidence-not-canonicalizable:${e.message}`]);
    }
    if (eh !== ar.evidence_hash)
      reasons.push("evidence-mismatch:recomputed-evidence_hash-differs");
  }
  return reasons.length > 0 ? bad(reasons) : ok();
}

/** §13.2 Chain integrity: gapless seq and prev_hash linkage. */
export function verifyChain(ars) {
  if (!Array.isArray(ars) || ars.length === 0) return bad(["empty-chain"]);
  const reasons = [];
  for (let i = 0; i < ars.length; i++) {
    const r = verifyRecord(ars[i]);
    if (r.result === "INVALID") reasons.push(...r.reasons.map((x) => `seq${ars[i]?.seq ?? i}:${x}`));
  }
  for (let i = 0; i < ars.length; i++) {
    const cur = ars[i];
    if (i === 0) {
      if (cur.seq !== 0) reasons.push(`chain-not-anchored-at-genesis:first-seq=${cur.seq}`);
      continue;
    }
    const prev = ars[i - 1];
    if (cur.seq !== prev.seq + 1) reasons.push(`gap:expected-seq-${prev.seq + 1}-got-${cur.seq}`);
    if (reasons.length > 0) continue; // shape already broken; skip hashing garbage
    let prevHash;
    try {
      prevHash = recordHash(prev);
    } catch {
      continue;
    }
    if (cur.prev_hash !== prevHash)
      reasons.push(`broken-link:seq-${cur.seq}-prev_hash-mismatch`);
  }
  return reasons.length > 0 ? bad(reasons) : ok();
}

/**
 * §13.3 Checkpoint verification: Merkle root over the range, operator
 * signature, prev_checkpoint_hash chain. Caveats:
 *  - UNANCHORED when no prior checkpoint is supplied and the checkpoint does
 *    not carry the genesis (all-zero) prev_checkpoint_hash.
 *  - UNWITNESSED when the witnesses array is empty/absent.
 *  - SEALED_HISTORY_PRESENT when notes.sealed_history is true.
 *  - PRIVATE_MODE for hs256 checkpoints (non-verifiable by third parties).
 */
export function verifyCheckpoint(cp, ars, prevCp, ed25519PubkeyPem, hmacSecret) {
  if (typeof cp !== "object" || cp === null || Array.isArray(cp))
    return bad(["not-a-json-object"]);
  const reasons = [];
  const caveats = [];
  for (const f of ["mca_version", "log_id", "checkpoint_id", "range", "merkle_root",
    "prev_checkpoint_hash", "hash_alg", "timestamp", "signature"]) {
    if (cp[f] === undefined || cp[f] === null) reasons.push(`missing-field:${f}`);
  }
  if (reasons.length > 0) return bad(reasons);
  if (cp.mca_version !== "0.1") reasons.push(`unsupported-version:${cp.mca_version}`);
  if (cp.hash_alg !== "sha-256") reasons.push(`unsupported-hash_alg:${cp.hash_alg}`);
  if (!HEX64.test(cp.merkle_root)) reasons.push("bad-merkle_root:not-64-lower-hex");
  if (!HEX64.test(cp.prev_checkpoint_hash)) reasons.push("bad-prev_checkpoint_hash:not-64-lower-hex");
  const { from_seq, to_seq } = cp.range ?? {};
  if (!Number.isInteger(from_seq) || !Number.isInteger(to_seq) || to_seq < from_seq || from_seq < 0)
    reasons.push("bad-range");

  // Merkle root over the supplied range must recompute to the claimed root.
  if (reasons.length === 0) {
    if (!Array.isArray(ars)) {
      reasons.push("records-required");
    } else if (ars.length !== to_seq - from_seq + 1) {
      reasons.push(`range-mismatch:expected-${to_seq - from_seq + 1}-records-got-${ars.length}`);
    } else {
      for (let i = 0; i < ars.length; i++) {
        if (ars[i]?.seq !== from_seq + i)
          reasons.push(`range-record-mismatch:position-${i}-has-seq-${ars[i]?.seq}`);
      }
      if (reasons.length === 0) {
        const recomputed = merkleRoot(ars.map((a) => recordHash(a)));
        if (recomputed !== cp.merkle_root) reasons.push("merkle-root-mismatch");
      }
    }

    // Checkpoint chain.
    if (prevCp !== undefined && prevCp !== null) {
      const expected = hashCanonical(prevCp);
      if (cp.prev_checkpoint_hash !== expected)
        reasons.push("checkpoint-chain-broken:prev_checkpoint_hash-mismatch");
    } else if (cp.prev_checkpoint_hash !== ZERO64) {
      caveats.push("UNANCHORED:no-prior-checkpoint-supplied");
    }

    if (cp.notes && cp.notes.sealed_history === true) caveats.push("SEALED_HISTORY_PRESENT");
    if (!Array.isArray(cp.witnesses) || cp.witnesses.length === 0) caveats.push("UNWITNESSED");

    // Operator signature over canonical checkpoint EXCLUDING signature & witnesses.
    const { signature, witnesses: _w, ...signedBody } = cp;
    let signedBytes;
    try {
      signedBytes = Buffer.from(canonicalize(signedBody), "utf8");
    } catch (e) {
      reasons.push(`checkpoint-not-canonicalizable:${e.message}`);
    }
    if (signedBytes && (typeof signature !== "object" || signature === null)) {
      reasons.push("bad-signature-object");
    } else if (signedBytes) {
      if (signature.alg === "ed25519") {
        if (!ed25519PubkeyPem) {
          reasons.push("no-ed25519-key-supplied");
        } else {
          let sig;
          try {
            sig = Buffer.from(String(signature.sig), "base64url");
          } catch {
            sig = null;
          }
          let valid = false;
          if (sig && sig.length === 64) {
            try {
              valid = cryptoVerify(null, signedBytes, ed25519PubkeyPem, sig);
            } catch {
              valid = false;
            }
          }
          if (!valid) reasons.push("bad-signature:ed25519-verify-failed");
        }
      } else if (signature.alg === "hs256") {
        // HMAC private mode (spec §7): never third-party verifiable.
        caveats.push("PRIVATE_MODE");
        if (hmacSecret !== undefined && hmacSecret !== null) {
          const expected = createHmac("sha256", hmacSecret).update(signedBytes).digest();
          let given;
          try {
            given = Buffer.from(String(signature.sig), "base64url");
          } catch {
            given = null;
          }
          if (!given || given.length !== expected.length || !timingSafeEqual(given, expected))
            reasons.push("bad-signature:hs256-verify-failed");
        }
        // Without the shared secret the signature is unverifiable by design;
        // PRIVATE_MODE caveat already surfaces that fact.
      } else {
        reasons.push(`unsupported-signature-alg:${signature.alg}`);
      }
    }
  }

  if (reasons.length > 0) return bad(reasons);
  return ok(caveats);
}

/** §13.4 Inclusion proof: AR + RFC 6962 audit path against a checkpoint root. */
export function verifyInclusion(ar, auditPathValue, cp) {
  if (typeof cp !== "object" || cp === null || !HEX64.test(cp?.merkle_root ?? ""))
    return bad(["bad-checkpoint:missing-or-malformed-merkle_root"]);
  const shape = [];
  if (typeof ar !== "object" || ar === null || Array.isArray(ar)) return bad(["not-a-json-object"]);
  validateRecordShape(ar, shape);
  if (shape.length > 0) return bad(shape);
  if (!Array.isArray(auditPathValue)) return bad(["bad-audit-path:not-an-array"]);
  let leaf;
  try {
    leaf = recordHash(ar);
  } catch (e) {
    return bad([`not-canonicalizable:${e.message}`]);
  }
  try {
    if (!verifyInclusionPath(leaf, auditPathValue, cp.merkle_root))
      return bad(["inclusion-proof-failed:path-does-not-reproduce-root"]);
  } catch (e) {
    return bad([`bad-audit-path:${e.message}`]);
  }
  return ok();
}
