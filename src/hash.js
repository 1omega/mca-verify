import { createHash, createPublicKey } from "node:crypto";
import { canonicalize } from "./canonicalize.js";

/** Genesis link value: 64 zero hex chars (MCA §3, §6). */
export const ZERO64 = "0".repeat(64);

/** Lowercase hex SHA-256 of a string or Buffer. */
export function sha256hex(input) {
  return createHash("sha256").update(input).digest("hex");
}

/** SHA-256 over the RFC 8785 canonical form of a JSON value, UTF-8 encoded. */
export function hashCanonical(value) {
  return sha256hex(Buffer.from(canonicalize(value), "utf8"));
}

/**
 * record_hash (MCA §3): SHA-256 over the canonical form of the Attestation
 * Record EXCLUDING any field named `record_hash`.
 */
export function recordHash(record) {
  const { record_hash: _omit, ...rest } = record;
  return hashCanonical(rest);
}

/**
 * Checkpoint body (MCA §6.3, v0.2): the Checkpoint with its TOP-LEVEL members
 * named `signature` and `witnesses` removed. Nothing else is removed: `notes`
 * and any member this verifier does not know stay in, and a member with one of
 * those names nested deeper (for example inside `notes`) stays in too.
 * These are the bytes the operator signs and every witness cosigns (§7, §8).
 */
export function checkpointBody(cp) {
  const { signature: _s, witnesses: _w, ...body } = cp;
  return body;
}

/**
 * checkpoint_hash (MCA §6.3, v0.2): SHA-256 over the canonical Checkpoint
 * body. It does not change when witness entries are added, removed or
 * reordered, or when `witnesses` is absent rather than empty. In v0.2 it is
 * the value the next Checkpoint carries as `prev_checkpoint_hash`.
 */
export function checkpointHash(cp) {
  return hashCanonical(checkpointBody(cp));
}

/**
 * key_id for an Ed25519 public key (addendum 0.1.1): "ed25519:" followed by
 * the first 16 lowercase hex characters of SHA-256 over the SPKI DER encoding.
 * This is how the IONDRA reference log derives its operator key_id.
 */
export function keyIdFromPublicKeyPem(pem) {
  const der = createPublicKey(pem).export({ type: "spki", format: "der" });
  return "ed25519:" + sha256hex(der).slice(0, 16);
}
