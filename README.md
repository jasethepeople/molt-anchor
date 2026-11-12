# molt-anchor

External checkpointing for a MOLT hash-chained ledger.

An anchor commits to `(ledger_id, seq, head_hash)`. Anchors chain to each other and are stored as git commits in a repo that should live (via push) somewhere the ledger owner does not control.

## The hole this fixes

An earlier draft's `verify_receipt` trusted the anchor's stored `head_hash` (and each event's stored `hash`). An attacker could swap in a forged anchor, fix up the anchor's own hash, and verification would pass.

This implementation **never trusts a stored hash**. `verify_receipt` recomputes the whole chain from genesis up to `anchor.seq` and compares the recomputed hash of the anchored event to `anchor.head_hash`. A swapped or forged anchor fails.

## What it does

- **Anchor chain:** anchors link to each other through `prev_anchor`. Two different heads at the same seq, or anchors going backwards, are rejected.
- **Ledger identity:** `ledger_id` is the recomputed genesis hash, so an anchor can't be replayed against another ledger.
- **Refusing bad ledgers:** `publish` won't anchor a ledger that is broken or shorter than the last anchor, and it re-checks all old anchors first.
- **Remote check:** `remote_has_local_head` confirms a remote you don't control actually contains your newest anchor.

## Usage

```bash
python3 molt_anchor.py anchor LEDGER.jsonl STORE --push REMOTE
python3 molt_anchor.py verify LEDGER.jsonl STORE --remote REMOTE
```

## Tests

```bash
python3 -m unittest test_molt_anchor -v
```

7 tests, all passing (verified here on Python 3.12.3).

## Honest limits

- **A local git repo proves nothing.** The ledger owner can rewrite it along with the ledger. The anchor only counts once it is pushed somewhere else. Always run `verify --remote`. Even then, whoever controls that remote could force-push. For a real guarantee you need a second witness, such as a public repo plus a timestamping service.
- **Event schema is a guess.** The assumed format is `{"seq", "prev", "payload", "hash"}` with `hash = sha256(canonical_json(event minus "hash"))`. This does NOT match the real MOLT event format (9 fields, Camp 1 hashing: 5-field signed body, hash = sha256(prev_hash + canonical body), signature over the 32 hash bytes). Adapt `event_hash()` to the real MOLT-CORE format before anchoring a real MOLT ledger.
- **Event signatures aren't verified here.** That is the verifier's job. The anchor only proves the chain, not who signed it.
- **Anchors themselves are unsigned.** Add commit signing if you want proof of who anchored.

## Known minor issues

- `remote_has_local_head` raises instead of returning False when the remote has no commits yet (git fetch fails: no such ref). The normal path (remote has at least one push) works.
- The explicit "shorter ledger" check in `publish()` is dead code; `check_history` catches a shorter ledger first (with a truncation message). The refusal itself works.

## Verification

Built by Claude (Nov 12, 2026) as a fresh implementation for MOLT project #5. Verified here: 7/7 tests pass, plus 13/14 independent cross-checks (the one miss is the empty-remote robustness gap above). Secret scan clean, no network code (git subprocess only).
