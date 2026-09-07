import { verifyVSR, verifySignature, verifyDelivery, verifyAnchor, wrapFetchWithVSR, vsrJcs } from "../dist/index.js";
import assert from "node:assert";
import { readFileSync } from "node:fs";

const doc = JSON.parse(readFileSync("/mnt/tempus-attestation-store/vsr-index/receipts/2026-09/4289c7e6-5f41-41f5-9ddb-e0af5d87b0b8.json", "utf8"));
let n = 0; const ok = (m) => { n++; };

// A1: null / undefined / garbage inputs never throw
for (const bad of [null, undefined, {}, [], "string", 42, { receipt: null }, { signature: {} }]) {
  const r = verifySignature(bad);
  assert.ok(["skipped","error","fail"].includes(r.state), "A1: " + JSON.stringify(bad) + " -> " + r.state);
}
ok("A1");

// A2: delivery with garbage never throws
for (const bad of [[null, null], [{}, {}], [{receipt:{delivery:{responseHash:"x"}}}, null], [doc, undefined]]) {
  const r = verifyDelivery(bad[0], bad[1]);
  assert.ok(["skipped","error","fail"].includes(r.state), "A2 -> " + r.state);
}
ok("A2");

// A3: signature stripped -> skipped (unattested), not fail
const noSig = JSON.parse(JSON.stringify(doc)); delete noSig.signature;
assert.equal(verifySignature(noSig).state, "skipped"); ok("A3");

// A4: corrupted base64 / hex in signature -> error or fail, never throw
const badB64 = JSON.parse(JSON.stringify(doc)); badB64.signature.signatures[0].publicKey = "!!!not-base64!!!";
assert.ok(["error","fail"].includes(verifySignature(badB64).state)); ok("A4");
const badHex = JSON.parse(JSON.stringify(doc)); badHex.signature.signatures[0].value = "zzzz";
assert.ok(["error","fail"].includes(verifySignature(badHex).state)); ok("A4b");

// A5: anchor-block tamper caught — attacker keeps valid sig but repoints anchor
const anchorSwap = JSON.parse(JSON.stringify(doc));
anchorSwap.receipt.anchor.payloadHash = "sha3-256:" + "ab".repeat(32);
anchorSwap.payloadHash = anchorSwap.receipt.anchor.payloadHash;
assert.equal(verifySignature(anchorSwap).state, "fail", "A5: repointed anchor must fail payloadHash reproduction"); ok("A5");

// A6: key-substitution — attacker re-signs tampered receipt with own key.
// Signature verifies (their key), so tier2 alone passes: DOCUMENTED limitation,
// binding signer identity to the expected oracle is the caller's check via publicKeyId.
// Assert the fields the caller needs are surfaced in the doc.
assert.ok(doc.signature.signatures[0].publicKeyId, "A6: publicKeyId present for identity binding"); ok("A6");

// A7: vsrJcs matches server semantics on tricky values
assert.equal(vsrJcs({b:1,a:[true,null,"x"],c:undefined}), '{"a":[true,null,"x"],"b":1}'); ok("A7");

// A8: wrapper never throws on non-JSON, empty body, network-shaped weirdness
const fakeFetch = async () => new Response("not json", { headers: { "content-type": "text/plain" } });
const w = wrapFetchWithVSR(fakeFetch);
const r8 = await w("http://x"); assert.ok(r8); ok("A8");
const fakeFetch2 = async () => new Response(JSON.stringify({plain:true}), { headers: { "content-type": "application/json" } });
const r8b = await wrapFetchWithVSR(fakeFetch2)("http://x");
assert.equal(r8b.verification.signature.state, "skipped"); ok("A8b");

// A9: anchor tier with unreachable endpoint -> pending (declared) not crash
const offline = await verifyAnchor(doc, { fetchImpl: async () => { throw new Error("net down"); } });
assert.ok(["pending","error"].includes(offline.state), "A9 -> " + offline.state); ok("A9");

// A10: body double-read safety — wrapper clones; caller can still read body
const fakeFetch3 = async () => new Response(JSON.stringify({hello:1}), { headers: { "content-type": "application/json" } });
const r10 = await wrapFetchWithVSR(fakeFetch3)("http://x");
const body10 = await r10.json();
assert.equal(body10.hello, 1, "A10: caller body read must survive"); ok("A10");

console.log("audit battery: " + n + "/" + n + " groups pass");
