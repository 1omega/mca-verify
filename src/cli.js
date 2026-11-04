#!/usr/bin/env node
/**
 * mca — MCA reference verifier CLI.
 *
 *   mca verify record <file> [--evidence f]
 *   mca verify chain <jsonl>
 *   mca verify checkpoint <cp> --records <jsonl> [--prev cp] [--key pem] [--hmac-secret s]
 *                         [--witness-key <key_id|witness_id>=<pem> ...]
 *   mca verify inclusion --record f --proof f --checkpoint f
 *       (--proof accepts the bare audit_path array or a log's inclusion-proof object)
 *
 * Exit codes: 0 = VALID, 1 = INVALID, 2 = usage/IO error.
 */

import { readFileSync } from "node:fs";
import { verifyRecord, verifyChain, verifyCheckpoint, verifyInclusion } from "./verify.js";

function die(msg) {
  console.error(`mca: error: ${msg}`);
  process.exit(2);
}

function readJson(path) {
  try {
    return JSON.parse(readFileSync(path, "utf8"));
  } catch (e) {
    die(`cannot read/parse ${path}: ${e.message}`);
  }
}

function readJsonl(path) {
  let text;
  try {
    text = readFileSync(path, "utf8");
  } catch (e) {
    die(`cannot read ${path}: ${e.message}`);
  }
  const rows = [];
  for (const [i, line] of text.split("\n").entries()) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    try {
      rows.push(JSON.parse(trimmed));
    } catch (e) {
      die(`invalid JSON on line ${i + 1} of ${path}: ${e.message}`);
    }
  }
  return rows;
}

/** Collect every occurrence of a repeatable `--name value` flag. */
function flagValues(args, name) {
  const out = [];
  for (;;) {
    const v = flagValue(args, name);
    if (v === undefined) return out;
    out.push(v);
  }
}

function flagValue(args, name) {
  const i = args.indexOf(name);
  if (i === -1) return undefined;
  const v = args[i + 1];
  if (v === undefined || v.startsWith("--")) die(`flag ${name} requires a value`);
  args.splice(i, 2);
  return v;
}

function report(label, r) {
  const reasons = r.reasons.length > 0 ? r.reasons.join("; ") : "none";
  console.log(`${label}: ${r.result}`);
  console.log(`reasons: ${reasons}`);
  process.exit(r.result === "VALID" ? 0 : 1);
}

const [verb, sub, ...rest] = process.argv.slice(2);
if (verb !== "verify" || !sub) {
  die("usage: mca verify <record|chain|checkpoint|inclusion> ...");
}

if (sub === "record") {
  const args = [...rest];
  const evidencePath = flagValue(args, "--evidence");
  const file = args.shift();
  if (!file || args.length > 0) die("usage: mca verify record <file> [--evidence f]");
  const ar = readJson(file);
  const evidence = evidencePath !== undefined ? readJson(evidencePath) : undefined;
  report("record", verifyRecord(ar, evidence));
} else if (sub === "chain") {
  const file = rest[0];
  if (!file || rest.length > 1) die("usage: mca verify chain <jsonl>");
  report("chain", verifyChain(readJsonl(file)));
} else if (sub === "checkpoint") {
  const args = [...rest];
  const recordsPath = flagValue(args, "--records");
  const prevPath = flagValue(args, "--prev");
  const keyPath = flagValue(args, "--key");
  const hmacSecret = flagValue(args, "--hmac-secret");
  const witnessSpecs = flagValues(args, "--witness-key");
  const cpFile = args.shift();
  if (!cpFile || !recordsPath || args.length > 0)
    die("usage: mca verify checkpoint <cp> --records <jsonl> [--prev cp] [--key pem] [--hmac-secret s] [--witness-key id=pem ...]");
  const witnessKeys = {};
  for (const spec of witnessSpecs) {
    const eq = spec.indexOf("=");
    if (eq <= 0) die(`--witness-key expects <key_id|witness_id>=<pem path>, got ${spec}`);
    const id = spec.slice(0, eq);
    const path = spec.slice(eq + 1);
    try {
      witnessKeys[id] = readFileSync(path, "utf8");
    } catch (e) {
      die(`cannot read witness key ${path}: ${e.message}`);
    }
  }
  let pem;
  if (keyPath !== undefined) {
    try {
      pem = readFileSync(keyPath, "utf8");
    } catch (e) {
      die(`cannot read key ${keyPath}: ${e.message}`);
    }
  }
  report(
    "checkpoint",
    verifyCheckpoint(
      readJson(cpFile),
      readJsonl(recordsPath),
      prevPath !== undefined ? readJson(prevPath) : undefined,
      pem,
      hmacSecret,
      { witnessKeys },
    ),
  );
} else if (sub === "inclusion") {
  const args = [...rest];
  const recordPath = flagValue(args, "--record");
  const proofPath = flagValue(args, "--proof");
  const checkpointPath = flagValue(args, "--checkpoint");
  if (!recordPath || !proofPath || !checkpointPath || args.length > 0)
    die("usage: mca verify inclusion --record f --proof f --checkpoint f");
  report(
    "inclusion",
    verifyInclusion(readJson(recordPath), readJson(proofPath), readJson(checkpointPath)),
  );
} else {
  die(`unknown subcommand: ${sub}`);
}
