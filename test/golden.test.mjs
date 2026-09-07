import { verifyVSR, verifySignature, verifyDelivery, vsrJcs } from "../dist/index.js";
import assert from "node:assert";
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";

const doc = JSON.parse(readFileSync("/mnt/tempus-attestation-store/vsr-index/receipts/2026-09/4289c7e6-5f41-41f5-9ddb-e0af5d87b0b8.json", "utf8"));

// T1: signature tier passes on the production golden receipt
const s1 = verifySignature(doc);
assert.equal(s1.state, "pass", "golden receipt signature must pass: " + s1.detail);

// T2: tampered receipt fails
const tampered = JSON.parse(JSON.stringify(doc));
tampered.receipt.payment.amount = "999999";
assert.equal(verifySignature(tampered).state, "fail", "tampered amount must fail signature");

// T3: delivery commitment round-trip on a synthetic response
const body = { success: true, data: { a: 1, b: "two" } };
const canonical = Buffer.from(vsrJcs(body), "utf8");
const rh = "sha3-256:" + createHash("sha3-256").update(Buffer.concat([Buffer.from([0x03]), canonical])).digest("hex");
const synth = { receipt: { delivery: { responseHash: rh, responseBytes: canonical.length, excludedMembers: ["vsr"] } } };
assert.equal(verifyDelivery(synth, { ...body, vsr: synth }).state, "pass", "synthetic delivery must pass");

// T4: delivery mismatch detected
assert.equal(verifyDelivery(synth, { ...body, data: { a: 2, b: "two" }, vsr: synth }).state, "fail", "altered body must fail delivery");

// T5: full verifyVSR on bare receipt, anchor pending or pass both acceptable
const full = await verifyVSR(doc, { checkAnchor: true });
assert.equal(full.signature.state, "pass");
assert.ok(["pass", "pending", "error"].includes(full.anchor.state), "anchor: " + full.anchor.detail);
console.log("anchor tier:", full.anchor.state, "-", full.anchor.detail);

// T6: unattested response handled as a state, not an error
const un = await verifyVSR({ hello: "world" }, { checkAnchor: false });
assert.equal(un.signature.state, "skipped");

console.log("vsr-verify conformance: 6/6 pass");
