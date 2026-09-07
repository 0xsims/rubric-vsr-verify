/**
 * Deterministic JSON canonicalization per RFC 8785 (JSON Canonicalization Scheme),
 * with the clarifications mandated by Rubric Verify Spec v1.0.0-rc1 §6.1.
 *
 * Ported from @rubric/verify v1.0.0-rc.1 src/canonical.ts (Phase 1 of the
 * Federation v1 Refactor). Dependency-free.
 *
 * RFC 8785 / Rubric Verify Spec §6.1 rules:
 *   1. Object keys MUST be sorted lexicographically (UTF-16 code unit order).
 *   2. There MUST be no whitespace between tokens.
 *   3. Numbers MUST be serialized using the shortest representation that
 *      round-trips through IEEE 754 double-precision parsing.
 *   4. Strings MUST be UTF-8 encoded.
 *   5. Boolean values MUST be `true` or `false` (lowercase).
 *   6. The null value MUST be `null` (lowercase).
 *   7. Arrays MUST preserve their input order.
 *   8. The output MUST be UTF-8 encoded; the canonical message bytes are the
 *      UTF-8 encoding of the canonicalized string.
 */

import { createHash } from 'crypto';

export class CanonicalInputError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'CanonicalInputError';
  }
}

/**
 * Canonicalize a JSON-compatible value to its RFC 8785 form (UTF-8 string).
 */
export function canonicalize(value: unknown): string {
  return serialize(value);
}

/**
 * UTF-8-encode the canonicalization of `value`.
 *
 * Equivalent to `new TextEncoder().encode(canonicalize(value))`.
 */
export function canonicalizeBytes(value: unknown): Uint8Array {
  return new TextEncoder().encode(canonicalize(value));
}

/**
 * SHA-256 hex digest of the canonicalization of `value`.
 *
 * Bare lowercase hex, no algorithm prefix, no `0x` prefix. Matches the
 * `payload_hash` format mandated by Rubric Verify Spec §6.3.
 */
export function canonicalSha256Hex(value: unknown): string {
  const bytes = canonicalizeBytes(value);
  return createHash('sha256').update(bytes).digest('hex');
}

function serialize(value: unknown): string {
  if (value === null) return 'null';
  if (value === undefined) {
    throw new CanonicalInputError('cannot canonicalize undefined; use null instead');
  }

  switch (typeof value) {
    case 'boolean':
      return value ? 'true' : 'false';
    case 'number':
      return serializeNumber(value);
    case 'string':
      return serializeString(value);
    case 'object':
      if (Array.isArray(value)) return serializeArray(value);
      return serializeObject(value as Record<string, unknown>);
    case 'bigint':
      throw new CanonicalInputError('bigint is not representable in canonical JSON');
    case 'function':
    case 'symbol':
      throw new CanonicalInputError(`unsupported value type: ${typeof value}`);
    default:
      throw new CanonicalInputError(`unknown value type: ${typeof value}`);
  }
}

function serializeArray(arr: unknown[]): string {
  const parts: string[] = [];
  for (const item of arr) {
    parts.push(serialize(item));
  }
  return '[' + parts.join(',') + ']';
}

function serializeObject(obj: Record<string, unknown>): string {
  // RFC 8785 §3.2.3: keys sorted by UTF-16 code unit order.
  // Default JS String comparison is UTF-16 code-unit ordering on BMP chars
  // and surrogate pairs alike.
  const keys = Object.keys(obj).sort();
  const parts: string[] = [];
  for (const key of keys) {
    const v = obj[key];
    if (v === undefined) continue; // RFC 8785: undefined-valued properties are omitted.
    parts.push(serializeString(key) + ':' + serialize(v));
  }
  return '{' + parts.join(',') + '}';
}

/**
 * Serialize a string per RFC 8785 §3.2.2.2 / RFC 8259 §7.
 *
 * Required escapes: " \ U+0000..U+001F.
 * Non-required characters (printable ASCII, non-ASCII Unicode) are emitted as-is.
 */
function serializeString(s: string): string {
  let out = '"';
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c < 0x20) {
      switch (c) {
        case 0x08:
          out += '\\b';
          break;
        case 0x09:
          out += '\\t';
          break;
        case 0x0a:
          out += '\\n';
          break;
        case 0x0c:
          out += '\\f';
          break;
        case 0x0d:
          out += '\\r';
          break;
        default:
          out += '\\u' + c.toString(16).padStart(4, '0');
      }
    } else if (c === 0x22) {
      out += '\\"';
    } else if (c === 0x5c) {
      out += '\\\\';
    } else {
      out += s[i];
    }
  }
  out += '"';
  return out;
}

/**
 * Serialize a number per RFC 8785 §3.2.2.3 — shortest round-tripping form.
 * NaN and ±Infinity are not representable in JSON; we throw.
 */
function serializeNumber(n: number): string {
  if (!Number.isFinite(n)) {
    throw new CanonicalInputError(`non-finite number is not representable in JSON: ${n}`);
  }
  if (Object.is(n, -0)) return '0';
  return String(n);
}
