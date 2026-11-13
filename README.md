# molt-anchor

A zero-dependency Node.js tool for checkpointing MOLT-CORE Camp 1 ledger heads in Git commits. It uses the nine-field event format and five-field hash/signature rules from `molt-core` and `molt-verify`; the included canonicalizer is copied from `molt-canonical`.

## What it checks

Before anchoring or accepting a receipt, the tool verifies canonical JSONL, the exact event fields, sequence and timestamp formats, previous-hash links, the Camp 1 SHA-256 hash, and each Ed25519 signature. It recomputes hashes from the events rather than trusting stored values. Anchors bind the genesis hash, sequence, and recomputed head hash; receipts reject truncation, rewrites, and a different ledger. Optional `trustedKeys` / `--trust` restrict accepted event signers.

Anchors link through `prev_anchor`, cannot move backwards, and `publish()` refuses a ledger inconsistent with an earlier anchor. A Git store is useful only when its commits are pushed to a remote independent of the ledger owner; local Git history alone is not an external checkpoint.

## Use

```sh
node molt-anchor.mjs anchor --ledger events.jsonl --store ./anchors [--trust PUBHEX,..] [--push REMOTE]
node molt-anchor.mjs verify --ledger events.jsonl --store ./anchors [--trust PUBHEX,..] [--remote REMOTE]
npm test
```

`store.pin()` returns the newest checkpoint as `{seq, hash}` for consumers that need to detect rollback. Checkpointing is manual. Anchors are not signed; add Git commit signing or an independent witness if proof of who created the checkpoint is required.

## Interoperability limits

The writer, verifier, and anchor use the same Camp 1 hash and signature scheme as `molt-event`, `molt-verify-ledger`, and the MOLT L1 package verifier. Cross-implementation agreement is confirmed for ASCII event content. MOLT-CORE leaves non-ASCII canonicalization open, so this tool does not claim Unicode interoperability with Foundry yet.

This replaces the repository's earlier Python prototype, whose guessed event schema did not match MOLT-CORE. The previous prototype remains available in Git history.
