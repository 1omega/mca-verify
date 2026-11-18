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
import { recordHash, hashCanonical, checkpointBody, checkpointHash, ZERO64 } from "./hash.js";
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

/**
 * How a Checkpoint's `prev_checkpoint_hash` is computed, selected by the
 * `mca_version` of the Checkpoint that CARRIES the link (it is inside the
 * signed body, so the operator signs the choice):
 *
 *  "0.1"  full form        SHA-256 over the canonical form of the WHOLE previous
 *                          Checkpoint, `signature` and `witnesses` included
 *                          (v0.1 §6). The value depends on which witness
 *                          entries the previous Checkpoint held at that moment.
 *  "0.2"  signed-body form SHA-256 over the canonical previous Checkpoint body
 *                          (v0.2 §6.3, `checkpointHash`). Independent of witnesses.
 */
const LINK_FORM = { "0.1": "full", "0.2": "signed-body" };
const CHECKPOINT_VERSIONS = new Set(Object.keys(LINK_FORM));

/** Up to this many witness entries, every ordered subset is tried (at most 4,095 hashes). */
const WITNESS_SUBSET_LIMIT = 12;
/** Up to this many, only leading runs are tried (at most 64 hashes). Beyond it, nothing is tried. */
const WITNESS_SEARCH_LIMIT = 64;

/**
 * v0.1 links only. The previous Checkpoint as supplied does not reproduce the
 * link. Find out whether it does once some of its witness entries are set
 * aside, i.e. whether the link did not cover those entries. Entry order is kept.
 *
 * Returns `{ uncovered, exhaustive }`. `uncovered` is the list of entries the
 * link does not cover, or null when no tried combination reproduces it.
 * `exhaustive` is false when the work bound stopped the search short, so a
 * null answer then means "not found among what was tried", not "no such subset".
 *
 * A match is as strong as an exact one for everything that matters: the hash
 * still covers the whole body and the operator signature of the previous
 * Checkpoint, so its signed content is the content the link committed to. It
 * shows that the link did not cover the set-aside entries; it does not show
 * when the Log merged them.
 *
 * The work is bounded because the previous Checkpoint is untrusted input: each
 * attempt serializes and hashes the whole object.
 */
function witnessesNotCoveredByLink(linkHash, prevCp) {
  const W = Array.isArray(prevCp.witnesses) ? prevCp.witnesses : [];
  if (W.length === 0) return { uncovered: null, exhaustive: true };
  if (W.length > WITNESS_SEARCH_LIMIT) return { uncovered: null, exhaustive: false };
  const { witnesses: _w, ...rest } = prevCp;
  const matches = (value) => {
    try {
      return hashCanonical(value) === linkHash;
    } catch {
      return false; // an entry with no canonical form cannot be part of a hashed link
    }
  };
  const tryKeep = (keepIdx) => {
    const kept = keepIdx.map((i) => W[i]);
    // When nothing is kept, the link may have been made over `"witnesses": []`
    // or over a Checkpoint with no `witnesses` member at all: both are tried.
    const hit = matches({ ...rest, witnesses: kept }) || (kept.length === 0 && matches(rest));
    return hit ? W.filter((_, i) => !keepIdx.includes(i)) : null;
  };
  if (W.length > WITNESS_SUBSET_LIMIT) {
    for (let k = W.length - 1; k >= 0; k--) {
      const uncovered = tryKeep([...Array(k).keys()]);
      if (uncovered) return { uncovered, exhaustive: false };
    }
    return { uncovered: null, exhaustive: false };
  }
  // Largest kept set first, so the fewest entries are reported.
  const masks = [];
  for (let m = 0; m < (1 << W.length) - 1; m++) masks.push(m);
  const bits = (m) => { let c = 0; for (let x = m; x; x >>= 1) c += x & 1; return c; };
  masks.sort((x, y) => bits(y) - bits(x) || x - y);
  for (const m of masks) {
    const uncovered = tryKeep([...Array(W.length).keys()].filter((i) => m & (1 << i)));
    if (uncovered) return { uncovered, exhaustive: true };
  }
  return { uncovered: null, exhaustive: true };
}

/**
 * Checkpoint chain link (§13.3): does `cp.prev_checkpoint_hash` commit to `prevCp`?
 * Pushes failures to `reasons` and caveats to `caveats`.
 */
function verifyCheckpointLink(cp, prevCp, reasons, caveats) {
  if (typeof prevCp !== "object" || Array.isArray(prevCp)) {
    reasons.push("bad-prev-checkpoint:not-a-json-object");
    return;
  }
  if (prevCp.log_id !== cp.log_id) {
    // Each Log (and each generation of a Log) has its own chain from genesis.
    reasons.push("checkpoint-chain-broken:prev-checkpoint-is-from-another-log");
    return;
  }
  if (prevCp.mca_version === "0.2" && cp.mca_version === "0.1") {
    // The link form never goes back: once a Log emits a 0.2 Checkpoint, every later one is 0.2.
    reasons.push("checkpoint-chain-broken:version-downgrade:0.1-after-0.2");
    return;
  }
  const link = cp.prev_checkpoint_hash;
  // The signed-body hash first: a 0.2 link depends on nothing else, so a witness
  // entry that cannot be serialized must not get in its way.
  let body;
  try {
    body = checkpointHash(prevCp);
  } catch (e) {
    reasons.push(`prev-checkpoint-not-canonicalizable:${e.message}`);
    return;
  }
  // The full form covers `witnesses` too and may have no canonical form even when the body does.
  let full = null;
  let fullError = null;
  try {
    full = hashCanonical(prevCp);
  } catch (e) {
    fullError = e;
  }
  if (LINK_FORM[cp.mca_version] === "signed-body") {
    if (link === body) return;
    // Name the commonest operator mistake instead of a bare mismatch.
    if (full !== null && link === full) reasons.push("checkpoint-chain-broken:link-is-the-0.1-full-form-in-a-0.2-checkpoint");
    else reasons.push("checkpoint-chain-broken:prev_checkpoint_hash-mismatch");
    return;
  }
  // v0.1 full form.
  if (full !== null && link === full) return;
  const { uncovered, exhaustive } = witnessesNotCoveredByLink(link, prevCp);
  if (uncovered !== null) {
    // The signed content of the previous Checkpoint is what the link committed
    // to; the link just does not cover these witness entries. Valid, and never silent.
    for (const [i, entry] of uncovered.entries())
      caveats.push(`PREV_WITNESS_ADDED_AFTER_LINK:${entry?.witness_id ?? `#${i}`}`);
    return;
  }
  if (link === body) reasons.push("checkpoint-chain-broken:link-is-the-0.2-signed-body-form-in-a-0.1-checkpoint");
  else if (!exhaustive)
    // Not every combination of witness entries was tried. The link may still be
    // sound: check it against the previous Checkpoint exactly as it stood when the link was made.
    reasons.push(`checkpoint-chain-broken:prev_checkpoint_hash-mismatch:witness-search-incomplete:${prevCp.witnesses.length}-entries`);
  else if (fullError) reasons.push(`prev-checkpoint-not-canonicalizable:${fullError.message}`);
  else reasons.push("checkpoint-chain-broken:prev_checkpoint_hash-mismatch");
}

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
 * signature, prev_checkpoint_hash chain. The chain link is checked in the form
 * the Checkpoint's own `mca_version` selects (see LINK_FORM). Caveats:
 *  - PREV_WITNESS_ADDED_AFTER_LINK:<witness_id> when a v0.1 link reproduces
 *    only after setting aside that witness entry of the previous Checkpoint:
 *    the link does not cover it (the signed content is unchanged).
 *  - UNANCHORED when no prior checkpoint is supplied and the checkpoint does
 *    not carry the genesis (all-zero) prev_checkpoint_hash.
 *  - UNWITNESSED when the witnesses array is empty/absent.
 *  - SEALED_HISTORY_PRESENT when notes.sealed_history is true.
 *  - PRIVATE_MODE for hs256 checkpoints (non-verifiable by third parties).
 */
export function verifyCheckpoint(cp, ars, prevCp, ed25519PubkeyPem, hmacSecret, opts = {}) {
  if (typeof cp !== "object" || cp === null || Array.isArray(cp))
    return bad(["not-a-json-object"]);
  const reasons = [];
  const caveats = [];
  for (const f of ["mca_version", "log_id", "checkpoint_id", "range", "merkle_root",
    "prev_checkpoint_hash", "hash_alg", "timestamp", "signature"]) {
    if (cp[f] === undefined || cp[f] === null) reasons.push(`missing-field:${f}`);
  }
  if (reasons.length > 0) return bad(reasons);
  if (!CHECKPOINT_VERSIONS.has(cp.mca_version)) reasons.push(`unsupported-version:${cp.mca_version}`);
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
        const leaves = [];
        for (let i = 0; i < ars.length; i++) {
          try {
            leaves.push(recordHash(ars[i]));
          } catch (e) {
            reasons.push(`record-not-canonicalizable:position-${i}:${e.message}`);
            break;
          }
        }
        if (reasons.length === 0 && merkleRoot(leaves) !== cp.merkle_root) reasons.push("merkle-root-mismatch");
      }
    }

    // Checkpoint chain.
    if (prevCp !== undefined && prevCp !== null) {
      verifyCheckpointLink(cp, prevCp, reasons, caveats);
    } else if (cp.prev_checkpoint_hash !== ZERO64) {
      caveats.push("UNANCHORED:no-prior-checkpoint-supplied");
    }

    if (cp.notes && cp.notes.sealed_history === true) caveats.push("SEALED_HISTORY_PRESENT");

    // Operator signature over canonical checkpoint EXCLUDING signature & witnesses.
    const { signature } = cp;
    let signedBytes;
    try {
      signedBytes = Buffer.from(canonicalize(checkpointBody(cp)), "utf8");
    } catch (e) {
      reasons.push(`checkpoint-not-canonicalizable:${e.message}`);
    }

    // Witness countersignatures (spec §8, addendum 0.1.1): each entry signs the
    // SAME canonical bytes as the operator. UNWITNESSED only when the array is
    // empty. For each entry: WITNESSED:<id> when a supplied witness key verifies
    // it, WITNESS_UNVERIFIED:<id> when no key for it was supplied, and INVALID
    // when a supplied key fails to verify it (a bad cosignature is a defect).
    if (!Array.isArray(cp.witnesses) || cp.witnesses.length === 0) {
      caveats.push("UNWITNESSED");
    } else if (signedBytes) {
      const keys = opts.witnessKeys ?? {};
      for (const [i, entry] of cp.witnesses.entries()) {
        const id = entry?.witness_id ?? `#${i}`;
        const pem = keys[entry?.key_id] ?? keys[entry?.witness_id];
        if (pem === undefined) {
          caveats.push(`WITNESS_UNVERIFIED:${id}`);
          continue;
        }
        const r = verifyWitness(cp, entry, pem);
        if (r.result === "VALID") caveats.push(`WITNESSED:${id}`);
        else reasons.push(`bad-witness-signature:${id}:${r.reasons.join(",")}`);
      }
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

/**
 * §8 Witness countersignature: Ed25519 over the canonical checkpoint excluding
 * `signature` and `witnesses` — the same bytes the operator signed. The entry
 * is `{ witness_id, key_id, alg: "ed25519", timestamp, sig }` (addendum 0.1.1).
 */
export function verifyWitness(cp, entry, witnessPubkeyPem) {
  if (typeof cp !== "object" || cp === null) return bad(["not-a-json-object"]);
  if (typeof entry !== "object" || entry === null) return bad(["bad-witness-entry"]);
  if (entry.alg !== "ed25519") return bad([`unsupported-witness-alg:${entry.alg}`]);
  if (!witnessPubkeyPem) return bad(["no-witness-key-supplied"]);
  let signedBytes;
  try {
    signedBytes = Buffer.from(canonicalize(checkpointBody(cp)), "utf8");
  } catch (e) {
    return bad([`checkpoint-not-canonicalizable:${e.message}`]);
  }
  let sig;
  try {
    sig = Buffer.from(String(entry.sig), "base64url");
  } catch {
    sig = null;
  }
  let valid = false;
  if (sig && sig.length === 64) {
    try {
      valid = cryptoVerify(null, signedBytes, witnessPubkeyPem, sig);
    } catch {
      valid = false;
    }
  }
  return valid ? ok() : bad(["ed25519-verify-failed"]);
}

/**
 * §13.4 Inclusion proof: AR + RFC 6962 audit path against a checkpoint root.
 *
 * `auditPathValue` is either the bare audit path array, or (addendum 0.1.1)
 * the inclusion-proof object a log serves:
 * `{ checkpoint_id, record_hash, leaf_index, tree_size, audit_path, merkle_root }`.
 * When the object names a `merkle_root`, `checkpoint_id` or `record_hash`, each
 * MUST agree with the supplied checkpoint/record or the proof is INVALID.
 */
export function verifyInclusion(ar, auditPathValue, cp) {
  if (typeof cp !== "object" || cp === null || !HEX64.test(cp?.merkle_root ?? ""))
    return bad(["bad-checkpoint:missing-or-malformed-merkle_root"]);
  const shape = [];
  if (typeof ar !== "object" || ar === null || Array.isArray(ar)) return bad(["not-a-json-object"]);
  validateRecordShape(ar, shape);
  if (shape.length > 0) return bad(shape);
  if (auditPathValue && typeof auditPathValue === "object" && !Array.isArray(auditPathValue)) {
    const wrapper = auditPathValue;
    const mismatch = [];
    if (wrapper.merkle_root !== undefined && wrapper.merkle_root !== cp.merkle_root)
      mismatch.push("proof-checkpoint-mismatch:merkle_root");
    if (wrapper.checkpoint_id !== undefined && cp.checkpoint_id !== undefined && wrapper.checkpoint_id !== cp.checkpoint_id)
      mismatch.push("proof-checkpoint-mismatch:checkpoint_id");
    if (wrapper.record_hash !== undefined) {
      let rh;
      try {
        rh = recordHash(ar);
      } catch (e) {
        return bad([`not-canonicalizable:${e.message}`]);
      }
      if (wrapper.record_hash !== rh) mismatch.push("proof-record-mismatch:record_hash");
    }
    if (mismatch.length > 0) return bad(mismatch);
    auditPathValue = wrapper.audit_path;
  }
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
