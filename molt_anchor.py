#!/usr/bin/env python3
"""molt-anchor: external checkpointing for a MOLT hash-chained ledger.

An anchor commits to (ledger_id, seq, head_hash). Anchors are chained to each
other and stored as git commits in a repo that should live (via push) somewhere
the ledger owner does not control.

KEY FIX vs. the draft: verification NEVER trusts a hash that is stored in the
anchor or in an event's "hash" field. It recomputes the whole chain from the
ledger up to anchor.seq, and compares the recomputed hash of the anchored event
to anchor.head_hash. A swapped / forged anchor therefore fails.

ASSUMED event format (adapt event_hash() to the real MOLT-CORE schema):
  {"seq": int, "prev": hex64, "payload": ..., "sig": ..., "hash": hex64}
  hash = sha256(canonical_json(event minus "hash")); genesis prev = "0"*64.
"""
import argparse, hashlib, json, os, subprocess, sys, tempfile, time
from dataclasses import dataclass

GENESIS_PREV = "0" * 64
ANCHOR_VERSION = 1


class AnchorError(Exception):
    pass


def canon(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode()


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def event_hash(ev: dict) -> str:
    return sha(canon({k: v for k, v in ev.items() if k != "hash"}))


def ledger_id(events) -> str:
    """Identity of a ledger = recomputed hash of its genesis event."""
    return event_hash(events[0])


def verify_chain(events, upto: int) -> str:
    """Recompute every hash and link from genesis through events[upto].
    Returns the RECOMPUTED hash of events[upto]. Raises AnchorError."""
    if upto < 0 or upto >= len(events):
        raise AnchorError(f"ledger has {len(events)} events; seq {upto} missing "
                          "(truncated or wrong ledger)")
    prev = GENESIS_PREV
    h = None
    for i in range(upto + 1):
        ev = events[i]
        if ev.get("seq") != i:
            raise AnchorError(f"event {i}: bad seq {ev.get('seq')!r}")
        if ev.get("prev") != prev:
            raise AnchorError(f"event {i}: prev does not link to event {i-1}")
        h = event_hash(ev)
        if ev.get("hash") != h:
            raise AnchorError(f"event {i}: stored hash != recomputed hash")
        prev = h
    return h


def _anchor_body(a: dict) -> dict:
    return {k: a[k] for k in ("v", "ledger_id", "seq", "head_hash", "prev_anchor", "ts")}


def anchor_hash(a: dict) -> str:
    return sha(canon(_anchor_body(a)))


def make_anchor(events, prev_anchor: str = GENESIS_PREV, ts=None) -> dict:
    if not events:
        raise AnchorError("empty ledger")
    seq = len(events) - 1
    head = verify_chain(events, seq)  # refuse to anchor a broken ledger
    a = {"v": ANCHOR_VERSION, "ledger_id": ledger_id(events), "seq": seq,
         "head_hash": head, "prev_anchor": prev_anchor,
         "ts": int(time.time()) if ts is None else ts}
    a["anchor_hash"] = anchor_hash(a)
    return a


@dataclass
class Result:
    ok: bool
    reason: str = "ok"

    def __bool__(self):
        return self.ok


def verify_receipt(events, anchor: dict, history=None) -> Result:
    """Check that `events` is consistent with `anchor` (and, optionally, with
    every anchor in `history`, which is validated as a chain)."""
    try:
        for k in ("v", "ledger_id", "seq", "head_hash", "prev_anchor", "ts", "anchor_hash"):
            if k not in anchor:
                raise AnchorError(f"anchor missing field {k}")
        if anchor["v"] != ANCHOR_VERSION:
            raise AnchorError("unsupported anchor version")
        if anchor_hash(anchor) != anchor["anchor_hash"]:
            raise AnchorError("anchor_hash does not match anchor body")
        if not events or ledger_id(events) != anchor["ledger_id"]:
            raise AnchorError("anchor is for a different ledger (genesis mismatch)")
        recomputed = verify_chain(events, anchor["seq"])      # <-- the hole fix
        if recomputed != anchor["head_hash"]:
            raise AnchorError("anchored head_hash != recomputed event hash "
                              "(ledger rewritten, or anchor swapped)")
        if history is not None:
            if anchor["anchor_hash"] not in [h["anchor_hash"] for h in history]:
                raise AnchorError("anchor not present in anchor history")
            check_history(events, history)
    except AnchorError as e:
        return Result(False, str(e))
    return Result(True)


def check_history(events, history):
    """Anchors form a chain, never go backwards, and every one matches the ledger."""
    prev, last_seq, heads = GENESIS_PREV, -1, {}
    for a in history:
        if anchor_hash(a) != a["anchor_hash"]:
            raise AnchorError(f"anchor seq {a['seq']}: anchor_hash mismatch")
        if a["prev_anchor"] != prev:
            raise AnchorError(f"anchor seq {a['seq']}: broken anchor chain")
        if a["seq"] < last_seq:
            raise AnchorError(f"anchor seq {a['seq']}: anchors went backwards")
        if heads.setdefault(a["seq"], a["head_hash"]) != a["head_hash"]:
            raise AnchorError(f"two different heads anchored at seq {a['seq']}")
        if verify_chain(events, a["seq"]) != a["head_hash"] or ledger_id(events) != a["ledger_id"]:
            raise AnchorError(f"anchor seq {a['seq']}: does not match ledger")
        prev, last_seq = a["anchor_hash"], a["seq"]


# ---------------------------------------------------------------- git store
def _git(repo, *args, check=True):
    env = dict(os.environ, GIT_TERMINAL_PROMPT="0")
    p = subprocess.run(["git", "-C", repo, "-c", "user.name=molt-anchor",
                        "-c", "user.email=anchor@molt.invalid", "-c", "commit.gpgsign=false",
                        *args], capture_output=True, text=True, env=env)
    if check and p.returncode:
        raise AnchorError(f"git {' '.join(args)}: {p.stderr.strip()}")
    return p


class GitAnchorStore:
    """Each anchor = one commit containing anchor.json. Git's own commit chain
    adds a second, independent ordering. Independence from the ledger owner
    comes from push() to a remote they do not control; a local repo alone
    proves nothing."""

    def __init__(self, path):
        self.path = path
        if not os.path.isdir(os.path.join(path, ".git")):
            os.makedirs(path, exist_ok=True)
            subprocess.run(["git", "init", "-q", "-b", "main", path], check=True)

    def history(self):
        p = _git(self.path, "log", "--reverse", "--format=%H", check=False)
        out = []
        for c in p.stdout.split():
            out.append(json.loads(_git(self.path, "show", f"{c}:anchor.json").stdout))
        return out

    def latest(self):
        h = self.history()
        return h[-1] if h else None

    def publish(self, events, ts=None) -> dict:
        last = self.latest()
        a = make_anchor(events, last["anchor_hash"] if last else GENESIS_PREV, ts)
        if last:
            check_history(events, self.history())            # old anchors must still hold
            if a["seq"] < last["seq"]:
                raise AnchorError("ledger is shorter than the last anchor")
            if a["seq"] == last["seq"]:
                raise AnchorError("nothing new to anchor")
        with open(os.path.join(self.path, "anchor.json"), "w") as f:
            json.dump(a, f, sort_keys=True, indent=1)
        _git(self.path, "add", "anchor.json")
        _git(self.path, "commit", "-q", "-m",
             f"anchor {a['ledger_id'][:12]} seq={a['seq']} head={a['head_hash'][:12]}")
        return a

    def push(self, remote, branch="main"):
        _git(self.path, "push", "-q", remote, f"HEAD:refs/heads/{branch}")

    def remote_has_local_head(self, remote, branch="main") -> bool:
        """True iff the remote's branch contains our newest anchor commit."""
        _git(self.path, "fetch", "-q", remote, branch)
        local = _git(self.path, "rev-parse", "HEAD").stdout.strip()
        return _git(self.path, "merge-base", "--is-ancestor", local,
                    "FETCH_HEAD", check=False).returncode == 0


# ---------------------------------------------------------------------- CLI
def load_ledger(path):
    with open(path) as f:
        return [json.loads(l) for l in f if l.strip()]


def main(argv=None):
    ap = argparse.ArgumentParser(prog="molt-anchor")
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("anchor"); a.add_argument("ledger"); a.add_argument("store")
    a.add_argument("--push", help="remote URL/path to push anchors to")
    v = sub.add_parser("verify"); v.add_argument("ledger"); v.add_argument("store")
    v.add_argument("--remote", help="also require this remote to contain the newest anchor")
    args = ap.parse_args(argv)
    events, store = load_ledger(args.ledger), GitAnchorStore(args.store)
    try:
        if args.cmd == "anchor":
            an = store.publish(events)
            if args.push:
                store.push(args.push)
            print(f"anchored seq={an['seq']} head={an['head_hash']}")
        else:
            hist = store.history()
            if not hist:
                print("FAIL: no anchors"); return 1
            r = verify_receipt(events, hist[-1], hist)
            if r and args.remote and not store.remote_has_local_head(args.remote):
                r = Result(False, "remote does not contain newest anchor")
            print("OK" if r else f"FAIL: {r.reason}")
            return 0 if r else 1
    except AnchorError as e:
        print(f"FAIL: {e}"); return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
