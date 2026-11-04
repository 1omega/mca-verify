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
 * key_id for an Ed25519 public key (addendum 0.1.1): "ed25519:" followed by
 * the first 16 lowercase hex characters of SHA-256 over the SPKI DER encoding.
 * This is how the IONDRA reference log derives its operator key_id.
 */
export function keyIdFromPublicKeyPem(pem) {
  const der = createPublicKey(pem).export({ type: "spki", format: "der" });
  return "ed25519:" + sha256hex(der).slice(0, 16);
}
