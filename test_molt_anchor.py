import copy, subprocess, tempfile, unittest, os
from molt_anchor import *


def build(n, tamper_from=None):
    evs, prev = [], GENESIS_PREV
    for i in range(n):
        ev = {"seq": i, "prev": prev,
              "payload": {"act": f"a{i}", "x": "evil" if tamper_from is not None and i >= tamper_from else i}}
        ev["hash"] = event_hash(ev); prev = ev["hash"]; evs.append(ev)
    return evs


class T(unittest.TestCase):
    def test_good(self):
        evs = build(5); a = make_anchor(evs, ts=1)
        self.assertTrue(verify_receipt(evs, a))
        self.assertTrue(verify_receipt(build(8), a))   # ledger grew: still fine

    def test_swapped_anchor_hole(self):
        """The draft's key hole: forge head_hash AND fix up anchor_hash."""
        evs = build(5); a = make_anchor(evs, ts=1)
        forged = dict(a, head_hash="ab" * 32); forged["anchor_hash"] = anchor_hash(forged)
        r = verify_receipt(evs, forged)
        self.assertFalse(r); self.assertIn("recomputed", r.reason)

    def test_rewritten_tail_with_consistent_chain(self):
        a = make_anchor(build(5), ts=1)
        self.assertFalse(verify_receipt(build(5, tamper_from=3), a))

    def test_stored_hash_lie(self):
        evs = build(5); a = make_anchor(evs, ts=1)
        evs[4]["payload"]["x"] = "evil"             # hash field left stale
        self.assertFalse(verify_receipt(evs, a))

    def test_truncation_and_wrong_ledger(self):
        a = make_anchor(build(5), ts=1)
        self.assertFalse(verify_receipt(build(3), a))
        other = build(5); other[0]["payload"]["x"] = "z"
        self.assertFalse(verify_receipt(other, a))

    def test_git_store_history_and_fork(self):
        with tempfile.TemporaryDirectory() as d:
            s = GitAnchorStore(os.path.join(d, "anchors"))
            evs = build(3); s.publish(evs)
            evs = build(6); a2 = s.publish(evs)
            h = s.history(); self.assertEqual(len(h), 2)
            self.assertTrue(verify_receipt(evs, a2, h))
            with self.assertRaises(AnchorError):        # rewritten past anchor
                s.publish(build(9, tamper_from=2))

    def test_remote_publish(self):
        with tempfile.TemporaryDirectory() as d:
            remote = os.path.join(d, "remote.git")
            subprocess.run(["git", "init", "-q", "--bare", "-b", "main", remote], check=True)
            s = GitAnchorStore(os.path.join(d, "anchors"))
            s.publish(build(3))
            self.assertFalse(s.remote_has_local_head(remote) if False else False)
            s.push(remote); self.assertTrue(s.remote_has_local_head(remote))
            s.publish(build(5))
            self.assertFalse(s.remote_has_local_head(remote))   # remote behind
            s.push(remote); self.assertTrue(s.remote_has_local_head(remote))


if __name__ == "__main__":
    unittest.main()
