# rubric-vsr-verify

Client-side verification of Verifiable Settlement Receipts (VSR v0.4) for x402 payments. Your agent paid; this proves what it got.

Three independent tiers, checked from the receipt document alone:

- **delivery** - the response bytes you received match the hash the seller committed to (local, dependency-free)
- **signature** - the receipt core is signed with ML-DSA-65 (FIPS 204, post-quantum), and the anchor's payloadHash reproduces from the signed content (local)
- **anchor** - the payloadHash is anchored on Hedera HCS (one HTTP call, async)

Never throws, never blocks: verification is evidence attached to the response, not interception of it. Unattested sellers surface as a state (`skipped`), not an error.

## Wrap your paid fetch

```typescript
import { wrapFetchWithVSR } from "rubric-vsr-verify";

const fetchPaid = wrapFetchWithPayment(fetch, client); // @x402/core
const fetchVerified = wrapFetchWithVSR(fetchPaid, {
  onVerified: (v, url) => log.info({ url, ...v }),
});

const res = await fetchVerified("https://api.example.com/paid-resource");
// res.verification = { delivery, signature, anchor } - each pass/fail/skipped/pending/error
```

## Verify a bare receipt

```typescript
import { verifyVSR } from "rubric-vsr-verify";
const result = await verifyVSR(receiptDocument); // e.g. from GET /v1/receipt/:id
```

## Honesty notes

- The anchor tier queries the issuer's discovery endpoint. A verifier who distrusts the issuer entirely can resolve the payloadHash against the public Hedera mirror node directly; a `mirrorDirect` option is planned.
- A `pass` on all three tiers proves delivery integrity, signer identity, and anchoring. It does not judge the *quality* of what was delivered - evidence, not arbitration.
- A valid signature proves the receipt was signed by the key it carries - it does not by itself prove that key belongs to the seller you meant to pay. Bind identity by checking `signature.signatures[0].publicKeyId` against the signer you expect (Rubric oracle keys are published at rubric-protocol.com/keys).
- Signature verification uses @noble/post-quantum (^0.3.0). Receipt and signer formats: https://rubric-protocol.com/specs/vsr-v0.4.md

## License

MIT (c) Echelon Intelligence Group LLC
