#!/usr/bin/env node
// molt-anchor (Node, Camp 1): external checkpoints of a MOLT ledger head, stored as git commits.
//
// An anchor commits to (ledger_id, seq, head_hash). ledger_id = hash of the genesis event.
// Anchors chain to each other (prev_anchor). A receipt is checked by RECOMPUTING the ledger's hash chain
// up to anchor.seq and comparing the recomputed hash to anchor.head_hash; stored hashes are never trusted.
// A local git repo proves nothing by itself: independence comes from pushing to a remote the ledger owner
// does not control, and from checking that remote (remoteHasHead).
import { createHash, createPublicKey, sign, verify as edVerify } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { canonicalizeJsonText } from './molt-canonical.mjs';

const ZERO = '0'.repeat(64);
const HEX64 = /^[0-9a-f]{64}$/;
const HEX128 = /^[0-9a-f]{128}$/;
const FIELDS = ['seq', 'ts', 'type', 'actor', 'payload', 'prev_hash', 'pub', 'sig', 'hash'];
const SPKI = Buffer.from('302a300506032b6570032100', 'hex');
const sha = v => createHash('sha256').update(v).digest('hex');
const isObj = v => v !== null && typeof v === 'object' && !Array.isArray(v);

export class AnchorError extends Error {}

// Camp 1 event builder (identical to molt-event.mjs), exported for tests.
export function buildEvent({ seq, ts, type, actor, payload, prevHash, publicHex, privateKey }) {
  const hash = sha(`${prevHash}${canonicalizeJsonText(JSON.stringify({ seq, ts, type, payload, actor }))}`);
  const sig = sign(null, Buffer.from(hash, 'hex'), privateKey).toString('hex');
  return { seq, ts, type, actor, payload, prev_hash: prevHash, pub: publicHex, sig, hash };
}

/** Fully verify a ledger text (every event: canonical, fields, chain, Camp 1 hash, signature, optional trusted keys). */
export function verifyLedgerText(text, { trustedKeys = null } = {}) {
  if (typeof text !== 'string') return { ok: false, reason: 'ledger is not text' };
  if (text !== '' && !text.endsWith('\n')) return { ok: false, reason: 'ledger is not newline-terminated' };
  if (trustedKeys !== null && (!Array.isArray(trustedKeys) || trustedKeys.some(key => typeof key !== 'string' || !HEX64.test(key)))) {
    return { ok: false, reason: 'trusted key list is invalid' };
  }
  const trusted = trustedKeys ? new Set(trustedKeys) : null;
  const lines = text === '' ? [] : text.split('\n');
  if (lines.at(-1) === '') lines.pop();
  const events = [], hashes = [];
  let prev = ZERO;
  for (let i = 0; i < lines.length; i += 1) {
    const w = `event ${i}`;
    let ev;
    try { ev = JSON.parse(lines[i]); } catch { return { ok: false, reason: `${w}: invalid JSON` }; }
    let c;
    try { c = canonicalizeJsonText(lines[i]); } catch { c = null; }
    if (c !== lines[i]) return { ok: false, reason: `${w}: not canonical` };
    if (!isObj(ev) || Object.keys(ev).length !== FIELDS.length || !FIELDS.every(f => Object.hasOwn(ev, f))) return { ok: false, reason: `${w}: wrong fields` };
    if (ev.seq !== i) return { ok: false, reason: `${w}: seq out of order` };
    if (!Number.isSafeInteger(ev.ts) || ev.ts < 0 || typeof ev.type !== 'string' || typeof ev.actor !== 'string' ||
        ![ev.prev_hash, ev.pub, ev.hash].every(h => typeof h === 'string' && HEX64.test(h)) || typeof ev.sig !== 'string' || !HEX128.test(ev.sig)) return { ok: false, reason: `${w}: bad field format` };
    if (ev.prev_hash !== prev) return { ok: false, reason: `${w}: chain broken` };
    const h = sha(`${prev}${canonicalizeJsonText(JSON.stringify({ seq: ev.seq, ts: ev.ts, type: ev.type, payload: ev.payload, actor: ev.actor }))}`);
    if (h !== ev.hash) return { ok: false, reason: `${w}: hash mismatch` };
    if (trusted && !trusted.has(ev.pub)) return { ok: false, reason: `${w}: signed by an untrusted key` };
    let good = false;
    try { good = edVerify(null, Buffer.from(h, 'hex'), createPublicKey({ key: Buffer.concat([SPKI, Buffer.from(ev.pub, 'hex')]), format: 'der', type: 'spki' }), Buffer.from(ev.sig, 'hex')); } catch { good = false; }
    if (!good) return { ok: false, reason: `${w}: bad signature` };
    events.push(ev); hashes.push(h); prev = h;
  }
  return { ok: true, events, hashes };
}

const body = a => ({ v: a.v, ledger_id: a.ledger_id, seq: a.seq, head_hash: a.head_hash, prev_anchor: a.prev_anchor, ts: a.ts });
export const anchorHash = a => sha(canonicalizeJsonText(JSON.stringify(body(a))));

export function makeAnchor(text, prevAnchor = ZERO, ts = Math.floor(Date.now() / 1000), opts = {}) {
  const v = verifyLedgerText(text, opts);
  if (!HEX64.test(prevAnchor)) throw new AnchorError('previous anchor hash is invalid');
  if (!Number.isSafeInteger(ts) || ts < 0) throw new AnchorError('anchor timestamp is invalid');
  if (!v.ok) throw new AnchorError(`refusing to anchor an invalid ledger: ${v.reason}`);
  if (v.events.length === 0) throw new AnchorError('refusing to anchor an empty ledger');
  const a = { v: 1, ledger_id: v.hashes[0], seq: v.events.length - 1, head_hash: v.hashes.at(-1), prev_anchor: prevAnchor, ts };
  return { ...a, anchor_hash: anchorHash(a) };
}

function checkShape(a) {
  if (!isObj(a)) throw new AnchorError('anchor is not an object');
  const fields = ['v', 'ledger_id', 'seq', 'head_hash', 'prev_anchor', 'ts', 'anchor_hash'];
  if (Object.keys(a).length !== fields.length || !fields.every(field => Object.hasOwn(a, field))) throw new AnchorError('anchor has wrong fields');
  if (a.v !== 1) throw new AnchorError('unsupported anchor version');
  if (!Number.isSafeInteger(a.seq) || a.seq < 0 || !Number.isSafeInteger(a.ts) || a.ts < 0) throw new AnchorError('anchor has bad seq or ts');
  for (const k of ['ledger_id', 'head_hash', 'prev_anchor', 'anchor_hash']) if (typeof a[k] !== 'string' || !HEX64.test(a[k])) throw new AnchorError(`anchor has bad ${k}`);
  if (anchorHash(a) !== a.anchor_hash) throw new AnchorError('anchor_hash does not match anchor body');
}

/** Check each anchor against the ledger and each other: chained, never backwards, one head per seq. */
export function checkHistory(v, history) {
  let prev = ZERO, last = -1;
  const heads = new Map();
  for (const a of history) {
    checkShape(a);
    if (a.prev_anchor !== prev) throw new AnchorError(`anchor seq ${a.seq}: broken anchor chain`);
    if (a.seq < last) throw new AnchorError(`anchor seq ${a.seq}: anchors went backwards`);
    if ((heads.get(a.seq) ?? a.head_hash) !== a.head_hash) throw new AnchorError(`two different heads anchored at seq ${a.seq}`);
    heads.set(a.seq, a.head_hash);
    matches(v, a);
    prev = a.anchor_hash; last = a.seq;
  }
}

function matches(v, a) {
  if (v.events.length === 0 || v.hashes[0] !== a.ledger_id) throw new AnchorError('anchor is for a different ledger (genesis mismatch)');
  if (a.seq >= v.events.length) throw new AnchorError(`ledger has ${v.events.length} events; anchored seq ${a.seq} is missing (truncated)`);
  if (v.hashes[a.seq] !== a.head_hash) throw new AnchorError('anchored head_hash != recomputed hash of that event (ledger rewritten or anchor swapped)');
}

/** The KEY CHECK: recompute, don't trust. Returns {ok, reason}. Never throws. */
export function verifyReceipt(text, anchor, { history = null, trustedKeys = null } = {}) {
  try {
    checkShape(anchor);
    const v = verifyLedgerText(text, { trustedKeys });
    if (!v.ok) throw new AnchorError(`ledger invalid: ${v.reason}`);
    matches(v, anchor);
    if (history) {
      if (!history.some(h => h.anchor_hash === anchor.anchor_hash)) throw new AnchorError('anchor not present in anchor history');
      checkHistory(v, history);
    }
    return { ok: true, reason: 'ok' };
  } catch (e) {
    return { ok: false, reason: e instanceof Error ? e.message : 'unexpected verification failure' };
  }
}

// ---- git store ----
function git(repo, ...args) {
  try {
    return execFileSync('git', ['-C', repo, '-c', 'user.name=molt-anchor', '-c', 'user.email=anchor@molt.invalid', '-c', 'commit.gpgsign=false', ...args],
      { encoding: 'utf8', env: { ...process.env, GIT_TERMINAL_PROMPT: '0' }, stdio: ['ignore', 'pipe', 'pipe'] });
  } catch (e) { throw new AnchorError(`git ${args[0]} failed: ${String(e.stderr ?? e.message).trim()}`); }
}

export class GitAnchorStore {
  constructor(path) {
    this.path = path;
    if (!existsSync(join(path, '.git'))) { mkdirSync(path, { recursive: true }); execFileSync('git', ['init', '-q', '-b', 'main', path]); }
  }
  hasCommits() { try { git(this.path, 'rev-parse', '--verify', '-q', 'HEAD'); return true; } catch { return false; } }
  history() {
    if (!this.hasCommits()) return [];
    return git(this.path, 'log', '--reverse', '--format=%H').split('\n').filter(Boolean).map(c => JSON.parse(git(this.path, 'show', `${c}:anchor.json`)));
  }
  latest() { return this.history().at(-1) ?? null; }
  /** Anchor the current ledger text. Old anchors must still hold, and the ledger must have grown. */
  publish(text, ts = Math.floor(Date.now() / 1000), opts = {}) {
    const hist = this.history(), last = hist.at(-1);
    const v = verifyLedgerText(text, opts);
    if (!v.ok) throw new AnchorError(`refusing to anchor an invalid ledger: ${v.reason}`);
    if (hist.length) checkHistory(v, hist);
    const a = makeAnchor(text, last ? last.anchor_hash : ZERO, ts, opts);
    if (last && a.seq === last.seq) throw new AnchorError('nothing new to anchor');
    writeFileSync(join(this.path, 'anchor.json'), JSON.stringify(a, null, 1) + '\n');
    git(this.path, 'add', 'anchor.json');
    git(this.path, 'commit', '-q', '-m', `anchor ${a.ledger_id.slice(0, 12)} seq=${a.seq} head=${a.head_hash.slice(0, 12)}`);
    return a;
  }
  push(remote, branch = 'main') { git(this.path, 'push', '-q', remote, `HEAD:refs/heads/${branch}`); }
  /** True iff the remote branch contains our newest anchor commit. */
  remoteHasHead(remote, branch = 'main') {
    try {
      git(this.path, 'fetch', '-q', remote, branch);
    } catch (e) {
      if (e instanceof AnchorError && /couldn't find remote ref|remote ref does not exist/i.test(e.message)) return false;
      throw e;
    }
    const local = git(this.path, 'rev-parse', 'HEAD').trim();
    try { git(this.path, 'merge-base', '--is-ancestor', local, 'FETCH_HEAD'); return true; } catch { return false; }
  }
  /** Newest anchored head as {seq, hash}: feed this to molt-grants createGuard({ pin }) to survive restarts. */
  pin() { const a = this.latest(); return a ? { seq: a.seq, hash: a.head_hash } : null; }
}

// ---- CLI ----
function cli(argv) {
  const o = new Map();
  for (let i = 1; i < argv.length; i += 2) o.set(argv[i], argv[i + 1]);
  const trust = o.get('--trust') ? o.get('--trust').split(',') : null;
  if (!['anchor', 'verify'].includes(argv[0]) || !o.get('--ledger') || !o.get('--store')) { console.error('usage: molt-anchor.mjs anchor|verify --ledger FILE --store DIR [--trust PUBHEX,..] [--push|--remote URL]'); return 2; }
  let text;
  try { text = readFileSync(o.get('--ledger'), 'utf8'); } catch { console.error('cannot read ledger'); return 2; }
  try {
    const store = new GitAnchorStore(o.get('--store'));
    if (argv[0] === 'anchor') {
      const a = store.publish(text, undefined, { trustedKeys: trust });
      if (o.get('--push')) store.push(o.get('--push'));
      console.log(`anchored seq=${a.seq} head=${a.head_hash}`); return 0;
    }
    const hist = store.history();
    if (!hist.length) { console.log('FAIL: no anchors'); return 1; }
    const r = verifyReceipt(text, hist.at(-1), { history: hist, trustedKeys: trust });
    if (r.ok && o.get('--remote') && !store.remoteHasHead(o.get('--remote'))) { console.log('FAIL: remote does not contain newest anchor'); return 1; }
    console.log(r.ok ? 'OK' : `FAIL: ${r.reason}`); return r.ok ? 0 : 1;
  } catch (e) { if (e instanceof AnchorError) { console.log(`FAIL: ${e.message}`); return 1; } throw e; }
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) process.exitCode = cli(process.argv.slice(2));
