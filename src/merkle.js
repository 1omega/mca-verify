/**
 * Merkle tree over record_hash leaves, RFC 6962 Section 2.1 construction.
 *
 *   leaf hash     = SHA-256(0x00 || leaf_bytes)
 *   interior hash = SHA-256(0x01 || left || right)
 *
 * Leaves are supplied as lowercase hex record_hash values. Bottom-up folding
 * with odd-node promotion is equivalent to the recursive MTH definition.
 */

import { createHash } from "node:crypto";

const LEAF_PREFIX = Buffer.from([0x00]);
const INTERIOR_PREFIX = Buffer.from([0x01]);

function sha256(buf) {
  return createHash("sha256").update(buf).digest();
}

export function leafHash(leafHex) {
  return sha256(Buffer.concat([LEAF_PREFIX, Buffer.from(leafHex, "hex")]));
}

export function interiorHash(left, right) {
  return sha256(Buffer.concat([INTERIOR_PREFIX, left, right]));
}

function foldLevel(level) {
  const next = [];
  for (let i = 0; i < level.length; i += 2) {
    next.push(i + 1 < level.length ? interiorHash(level[i], level[i + 1]) : level[i]);
  }
  return next;
}

/** Merkle root (hex) over an array of hex leaf values. Empty input hashes the empty string, per RFC 6962. */
export function merkleRoot(leavesHex) {
  if (leavesHex.length === 0) return sha256(Buffer.alloc(0)).toString("hex");
  let level = leavesHex.map(leafHash);
  while (level.length > 1) level = foldLevel(level);
  return level[0].toString("hex");
}

/**
 * Generate the RFC 6962 audit path for the leaf at `index`.
 * Returns an ordered array of { position, hash } steps, bottom-up:
 * `position` states where the SIBLING sits relative to the running node
 * ("left"  => node = H(0x01 || sibling || node),
 *  "right" => node = H(0x01 || node || sibling)).
 */
export function auditPath(leavesHex, index) {
  if (!Number.isInteger(index) || index < 0 || index >= leavesHex.length) {
    throw new RangeError(`leaf index ${index} out of range (0..${leavesHex.length - 1})`);
  }
  const path = [];
  let level = leavesHex.map(leafHash);
  let idx = index;
  while (level.length > 1) {
    const nodeIsRightChild = idx % 2 === 1;
    const siblingIdx = nodeIsRightChild ? idx - 1 : idx + 1;
    if (siblingIdx < level.length) {
      path.push({
        position: nodeIsRightChild ? "left" : "right",
        hash: level[siblingIdx].toString("hex"),
      });
    }
    idx = Math.floor(idx / 2);
    level = foldLevel(level);
  }
  return path;
}

/** Fold an audit path from a hex leaf and compare against an expected hex root. */
export function verifyInclusionPath(leafHex, path, expectedRootHex) {
  let node = leafHash(leafHex);
  for (const step of path) {
    const sibling = Buffer.from(step.hash, "hex");
    node = step.position === "left" ? interiorHash(sibling, node) : interiorHash(node, sibling);
  }
  return node.toString("hex") === String(expectedRootHex).toLowerCase();
}
