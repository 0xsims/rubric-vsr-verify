// rubric-vsr-verify: client-side verification of Verifiable Settlement
// Receipts (VSR v0.4). Three independent tiers, never throws:
//   delivery  - response hash matches the receipt commitment (local, free)
//   signature - ML-DSA-65 over the receipt core, payloadHash reproduced (local)
//   anchor    - payloadHash resolvable on Hedera HCS (network, async)
//
// TWO canonicalizers by design, matching the emitter exactly:
//   - delivery hashes use the VSR JCS subset (vsr.ts vsrJcs semantics)
//   - the signature covers canonicalize() (RFC 8785, canonical.ts) over the
//     receipt WITHOUT its anchor block (sign-then-anchor construction)
// Do not "simplify" to one canonicalizer: numbers can serialize differently.

import { ml_dsa65 } from "@noble/post-quantum/ml-dsa";
import { createHash } from "crypto";
import { canonicalize } from "./canonical.js";

const TAG_REQ = 0x02, TAG_RESP = 0x03, TAG_RCPT = 0x04;

function sha3Tagged(tag: number, payload: Buffer): string {
  return "sha3-256:" + createHash("sha3-256")
    .update(Buffer.concat([Buffer.from([tag]), payload])).digest("hex");
}

// VSR JCS subset (port of vsr.ts vsrJcs): key sort, no whitespace,
// undefined dropped, JSON.stringify scalars.
export function vsrJcs(v: any): string {
  if (v === null) return "null";
  if (typeof v === "number" || typeof v === "boolean" || typeof v === "string") return JSON.stringify(v);
  if (Array.isArray(v)) return "[" + v.map(vsrJcs).join(",") + "]";
  if (typeof v === "object") {
    const keys = Object.keys(v).filter(k => v[k] !== undefined).sort();
    return "{" + keys.map(k => JSON.stringify(k) + ":" + vsrJcs(v[k])).join(",") + "}";
  }
  return "null";
}

export type TierState = "pass" | "fail" | "skipped" | "pending" | "error";
export interface VerificationResult {
  delivery: { state: TierState; detail: string };
  signature: { state: TierState; detail: string };
  anchor: { state: TierState; detail: string };
  receiptId?: string;
}

/** Tier 1: does the delivered response match the receipt's commitment?
 *  `responseJson` is the parsed body AS RECEIVED (vsr member included). */
export function verifyDelivery(vsrDoc: any, responseJson: any): { state: TierState; detail: string } {
  try {
    const d = vsrDoc?.receipt?.delivery;
    if (!d?.responseHash) return { state: "skipped", detail: "receipt carries no delivery commitment" };
    const body = { ...responseJson };
    for (const m of d.excludedMembers ?? ["vsr"]) delete body[m];
    const canonical = Buffer.from(vsrJcs(body), "utf8");
    if (typeof d.responseBytes === "number" && canonical.length !== d.responseBytes)
      return { state: "fail", detail: `canonical length ${canonical.length} != committed responseBytes ${d.responseBytes}` };
    const got = sha3Tagged(TAG_RESP, canonical);
    return got === d.responseHash
      ? { state: "pass", detail: "response matches delivery commitment" }
      : { state: "fail", detail: `responseHash mismatch: computed ${got.slice(0, 30)}..., receipt commits ${String(d.responseHash).slice(0, 30)}...` };
  } catch (e: any) { return { state: "error", detail: "delivery check errored: " + (e?.message ?? e) }; }
}

/** Tier 2: ML-DSA-65 signature over the receipt core (anchor stripped),
 *  plus reproduction of the payloadHash the anchor commits to. */
export function verifySignature(vsrDoc: any): { state: TierState; detail: string } {
  try {
    const sig = vsrDoc?.signature?.signatures?.[0];
    if (!sig?.publicKey || !sig?.value) return { state: "skipped", detail: "no signature block present (unattested)" };
    const core = { ...vsrDoc.receipt };
    delete core.anchor;
    const canonical = canonicalize(core);
    const msg = new TextEncoder().encode(canonical);
    const pk = new Uint8Array(Buffer.from(sig.publicKey, "base64"));
    const sg = new Uint8Array(Buffer.from(sig.value, "hex"));
    const ok = ml_dsa65.verify(pk, msg, sg);
    if (!ok) return { state: "fail", detail: "ML-DSA-65 signature invalid over receipt core" };
    const want = vsrDoc.payloadHash ?? vsrDoc.receipt?.anchor?.payloadHash;
    if (want) {
      const got = sha3Tagged(TAG_RCPT, Buffer.from(canonical, "utf8"));
      if (got !== want) return { state: "fail", detail: "signature valid but payloadHash does not reproduce - anchor binds to different content" };
    }
    return { state: "pass", detail: "ML-DSA-65 valid; payloadHash reproduced; anchor binds to signed core" };
  } catch (e: any) { return { state: "error", detail: "signature check errored: " + (e?.message ?? e) }; }
}

/** Tier 3: is the payloadHash anchored? Uses the receipt's own discovery
 *  endpoint; falls back to "pending" per the receipt's declared status. */
export async function verifyAnchor(vsrDoc: any, opts: { fetchImpl?: typeof fetch; timeoutMs?: number } = {}): Promise<{ state: TierState; detail: string }> {
  try {
    const a = vsrDoc?.receipt?.anchor;
    if (!a?.payloadHash) return { state: "skipped", detail: "no anchor block" };
    const f = opts.fetchImpl ?? fetch;
    const hash = String(a.payloadHash).replace("sha3-256:", "");
    const url = "https://rubric-protocol.com/verify/v1/by-payload-hash/" + hash;
    const r = await f(url, { signal: AbortSignal.timeout(opts.timeoutMs ?? 8000) });
    if (r.ok) {
      const j: any = await r.json().catch(() => null);
      if (j && (j.found === true || j.sequenceNumber || j.anchored)) {
        const seq = j.sequenceNumber ?? j.seq ?? null;
        return { state: "pass", detail: "anchored" + (j.anchoredAt ? " at " + j.anchoredAt : "") + " (attestation " + (j.attestationId ?? "?") + (seq ? ", seq " + seq : "") + ")" };
      }
    }
    return a.status === "pending"
      ? { state: "pending", detail: "receipt is signed but not yet anchored (declared pending; typically resolves within a minute)" }
      : { state: "fail", detail: "anchor not resolvable at discovery endpoint (HTTP " + r.status + ")" };
  } catch (e: any) { return { state: "error", detail: "anchor check errored: " + (e?.message ?? e) }; }
}

/** All three tiers over a parsed response body containing a `vsr` member. */
export async function verifyVSR(responseJson: any, opts: { checkAnchor?: boolean; fetchImpl?: typeof fetch } = {}): Promise<VerificationResult> {
  const vsrDoc = responseJson?.vsr ?? responseJson;
  const out: VerificationResult = {
    delivery: responseJson?.vsr ? verifyDelivery(vsrDoc, responseJson) : { state: "skipped", detail: "verifying a bare receipt document; no response body to check" },
    signature: verifySignature(vsrDoc),
    anchor: { state: "skipped", detail: "anchor check disabled" },
    receiptId: vsrDoc?.receipt?.receiptId,
  };
  if (opts.checkAnchor !== false) out.anchor = await verifyAnchor(vsrDoc, opts);
  return out;
}

/** Wrap a fetch (typically wrapFetchWithPayment's output). Never throws,
 *  never alters the response; attaches evidence via onVerified. */
export function wrapFetchWithVSR(
  fetchImpl: typeof fetch,
  opts: { onVerified?: (v: VerificationResult, url: string) => void; checkAnchor?: boolean } = {},
): typeof fetch {
  return (async (input: any, init?: any) => {
    const res = await fetchImpl(input, init);
    try {
      const ct = res.headers?.get?.("content-type") ?? "";
      if (ct.includes("application/json")) {
        const body = await res.clone().json().catch(() => null);
        if (body && body.vsr) {
          const v = await verifyVSR(body, { checkAnchor: opts.checkAnchor });
          try { opts.onVerified?.(v, String(typeof input === "string" ? input : input?.url ?? "")); } catch {}
          (res as any).verification = v;
        } else if (body) {
          const v: VerificationResult = {
            delivery: { state: "skipped", detail: "no vsr member in response" },
            signature: { state: "skipped", detail: "unattested delivery: seller emitted no receipt" },
            anchor: { state: "skipped", detail: "unattested" },
          };
          try { opts.onVerified?.(v, String(typeof input === "string" ? input : input?.url ?? "")); } catch {}
          (res as any).verification = v;
        }
      }
    } catch { /* evidence, not interception: the response always returns */ }
    return res;
  }) as typeof fetch;
}
