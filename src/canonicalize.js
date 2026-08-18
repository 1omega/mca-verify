/**
 * RFC 8785 JSON Canonicalization Scheme (JCS).
 *
 * - Object keys sorted recursively by UTF-16 code units. JavaScript's default
 *   Array.prototype.sort() comparator orders strings by UTF-16 code units,
 *   which is exactly the JCS ordering.
 * - Strings/numbers serialized with JSON.stringify, whose output conforms to
 *   the JCS serialization rules for ECMAScript values.
 * - Non-finite numbers (NaN, ±Infinity) are rejected: they have no JSON
 *   representation and therefore no canonical form.
 */

function serialize(value) {
  if (value === null) return "null";
  const t = typeof value;
  if (t === "boolean") return value ? "true" : "false";
  if (t === "number") {
    if (!Number.isFinite(value)) {
      throw new TypeError("JCS: non-finite number has no canonical form");
    }
    return JSON.stringify(value);
  }
  if (t === "string") return JSON.stringify(value);
  if (t === "bigint") throw new TypeError("JCS: bigint is not a JSON value");
  if (Array.isArray(value)) {
    return "[" + value.map(serialize).join(",") + "]";
  }
  if (t === "object") {
    const keys = Object.keys(value).filter(
      (k) => value[k] !== undefined && typeof value[k] !== "function",
    );
    keys.sort();
    return (
      "{" +
      keys.map((k) => JSON.stringify(k) + ":" + serialize(value[k])).join(",") +
      "}"
    );
  }
  throw new TypeError(`JCS: unsupported value type "${t}"`);
}

/** Canonicalize any JSON value to its RFC 8785 UTF-8 string form. */
export function canonicalize(value) {
  return serialize(value);
}
