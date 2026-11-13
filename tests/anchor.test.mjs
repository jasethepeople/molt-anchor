import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, createPublicKey, generateKeyPairSync, verify } from 'node:crypto';
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { anchorHash, buildEvent, GitAnchorStore, makeAnchor, verifyLedgerText, verifyReceipt } from '../molt-anchor.mjs';
import { canonicalizeJsonText } from '../molt-canonical.mjs';

const ZERO = '0'.repeat(64);
const SPKI = Buffer.from('302a300506032b6570032100', 'hex');
const samplePath = new URL('./fixtures/camp1-sample-good.events.jsonl', import.meta.url);
const scriptPath = new URL('../molt-anchor.mjs', import.meta.url);

function makeSigner() {
  const pair = generateKeyPairSync('ed25519');
  const publicBytes = Buffer.from(pair.publicKey.export({ format: 'der', type: 'spki' })).subarray(-32);
  return { privateKey: pair.privateKey, publicBytes, publicHex: publicBytes.toString('hex') };
}

function makeLedger(payloads, signer = makeSigner()) {
  let previousHash = ZERO;
  const events = payloads.map((payload, seq) => {
    const event = buildEvent({
      seq,
      ts: 1700000000 + seq,
      type: 'record.created',
      actor: 'test-suite',
      payload,
      prevHash: previousHash,
      publicHex: signer.publicHex,
      privateKey: signer.privateKey,
    });
    previousHash = event.hash;
    return event;
  });
  return {
    signer,
    events,
    text: `${events.map(event => canonicalizeJsonText(JSON.stringify(event))).join('\n')}\n`,
  };
}

function tempDir() {
  return mkdtemp(join(tmpdir(), 'molt-anchor-'));
}

test('accepts the MOLT-CORE sample-good ledger and reproduces its known head', async () => {
  const text = await readFile(samplePath, 'utf8');
  const result = verifyLedgerText(text);
  assert.equal(result.ok, true);
  assert.equal(result.events.length, 2);
  assert.equal(result.hashes[0], '9e5ee6e3e42504b009d4efdc837ea1d4a0ba82ad9186faadd7ced3e88efacc81');
  assert.equal(result.hashes[1], '0c2d611f3177d7d971aa5df569e972d50964cb738899b3b360d1a8b52d036ca8');
  const anchor = makeAnchor(text, ZERO, 1750000000);
  assert.equal(anchor.ledger_id, result.hashes[0]);
  assert.equal(anchor.head_hash, result.hashes[1]);
  assert.equal(anchor.anchor_hash, anchorHash(anchor));
});

test('builds and verifies Camp 1 events for every JSON payload type', () => {
  const { signer, events, text } = makeLedger([{ kind: 'object' }, ['array', 2], 'string', 7, true, null]);
  const result = verifyLedgerText(text);
  assert.equal(result.ok, true);
  assert.deepEqual(events.map(event => event.seq), [0, 1, 2, 3, 4, 5]);
  for (const event of events) {
    const body = { seq: event.seq, ts: event.ts, type: event.type, payload: event.payload, actor: event.actor };
    const expectedHash = createHash('sha256')
      .update(`${event.prev_hash}${canonicalizeJsonText(JSON.stringify(body))}`, 'utf8')
      .digest('hex');
    const publicKey = createPublicKey({ key: Buffer.concat([SPKI, signer.publicBytes]), format: 'der', type: 'spki' });
    assert.equal(event.hash, expectedHash);
    assert.equal(verify(null, Buffer.from(expectedHash, 'hex'), publicKey, Buffer.from(event.sig, 'hex')), true);
  }
});

test('rejects missing final newline, non-canonical JSON, tampering, and invalid trust lists', async () => {
  const { text } = makeLedger([{ n: 1 }, { n: 2 }]);
  assert.equal(verifyLedgerText(text.slice(0, -1)).reason, 'ledger is not newline-terminated');
  assert.match(verifyLedgerText(text.replace('"n":1', '"n": 1')).reason, /not canonical/);
  assert.match(verifyLedgerText(text.replace('"n":1', '"n":3')).reason, /hash mismatch/);
  assert.equal(verifyLedgerText(text, { trustedKeys: ['bad'] }).reason, 'trusted key list is invalid');
  const signer = makeLedger([{ n: 1 }]).signer;
  assert.match(verifyLedgerText(text, { trustedKeys: [signer.publicHex] }).reason, /untrusted key/);
});

test('rejects malformed anchor metadata and unknown fields', () => {
  const { text } = makeLedger([{ n: 1 }]);
  const anchor = makeAnchor(text, ZERO, 10);
  assert.throws(() => makeAnchor(text, 'bad', 10), /previous anchor hash/);
  assert.throws(() => makeAnchor(text, ZERO, -1), /anchor timestamp/);
  assert.match(verifyReceipt(text, { ...anchor, extra: true }).reason, /wrong fields/);
});

test('receipt rejects a forged head, truncation, and a rewritten but valid tail', () => {
  const signer = makeSigner();
  const original = makeLedger([{ n: 0 }, { n: 1 }, { n: 2 }, { n: 3 }], signer);
  const anchor = makeAnchor(original.text, ZERO, 1);
  const forged = { ...anchor, head_hash: 'ab'.repeat(32) };
  forged.anchor_hash = anchorHash(forged);
  assert.match(verifyReceipt(original.text, forged).reason, /anchored head_hash/);
  const truncated = makeLedger([{ n: 0 }, { n: 1 }], signer);
  assert.match(verifyReceipt(truncated.text, anchor).reason, /truncated/);
  const rewritten = makeLedger([{ n: 0 }, { n: 1 }, { n: 'changed' }, { n: 3 }], signer);
  assert.equal(verifyLedgerText(rewritten.text).ok, true);
  assert.match(verifyReceipt(rewritten.text, anchor).reason, /anchored head_hash/);
});

test('anchor history checks the chain and blocks rollback', async t => {
  const signer = makeSigner();
  const { events, text } = makeLedger([{ n: 0 }, { n: 1 }, { n: 2 }, { n: 3 }], signer);
  const firstText = `${events.slice(0, 2).map(event => canonicalizeJsonText(JSON.stringify(event))).join('\n')}\n`;
  const first = makeAnchor(firstText, ZERO, 1);
  const second = makeAnchor(text, first.anchor_hash, 2);
  assert.equal(verifyReceipt(text, second, { history: [first, second] }).ok, true);
  assert.match(verifyReceipt(text, second, { history: [second] }).reason, /broken anchor chain/);

  const dir = await tempDir();
  t.after(() => rm(dir, { recursive: true, force: true }));
  const store = new GitAnchorStore(join(dir, 'store'));
  const storedFirst = store.publish(firstText, 1);
  const storedSecond = store.publish(text, 2);
  assert.equal(storedSecond.prev_anchor, storedFirst.anchor_hash);
  assert.deepEqual(store.pin(), { seq: 3, hash: storedSecond.head_hash });
  assert.equal(verifyReceipt(text, storedSecond, { history: store.history() }).ok, true);
  assert.throws(() => store.publish(text, 3), /nothing new to anchor/);
  const shorter = makeLedger([{ n: 0 }], signer);
  assert.throws(() => store.publish(shorter.text, 4), /truncated/);
});

test('remote check returns false for an empty branch, then confirms pushed anchors', async t => {
  const dir = await tempDir();
  t.after(() => rm(dir, { recursive: true, force: true }));
  const remote = join(dir, 'remote.git');
  execFileSync('git', ['init', '-q', '--bare', '-b', 'main', remote]);
  const store = new GitAnchorStore(join(dir, 'store'));
  store.publish(makeLedger([{ n: 0 }]).text, 1);
  assert.equal(store.remoteHasHead(remote), false);
  store.push(remote);
  assert.equal(store.remoteHasHead(remote), true);
});

test('CLI anchors and verifies the sample, then rejects changed ledger content', async t => {
  const dir = await tempDir();
  t.after(() => rm(dir, { recursive: true, force: true }));
  const ledgerPath = join(dir, 'events.jsonl');
  const storePath = join(dir, 'store');
  const text = await readFile(samplePath, 'utf8');
  await writeFile(ledgerPath, text);
  const run = (...args) => spawnSync(process.execPath, [scriptPath.pathname, ...args, '--ledger', ledgerPath, '--store', storePath], { encoding: 'utf8' });
  const anchored = run('anchor');
  assert.equal(anchored.status, 0, anchored.stderr);
  assert.match(anchored.stdout, /^anchored seq=1 head=[0-9a-f]{64}\n$/);
  assert.equal(run('verify').stdout, 'OK\n');
  await writeFile(ledgerPath, text.replace('"score":1', '"score":2'));
  const changed = run('verify');
  assert.equal(changed.status, 1);
  assert.match(changed.stdout, /^FAIL:/);
});
