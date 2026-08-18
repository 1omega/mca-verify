import { createHash } from "node:crypto";
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
