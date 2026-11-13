#!/usr/bin/env node
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { TextDecoder } from 'node:util';
import { pathToFileURL } from 'node:url';

class JsonValidator {
  constructor(text) {
    this.text = text;
    this.index = 0;
  }

  fail(message) {
    throw new Error(`Invalid JSON: ${message} at position ${this.index}`);
  }

  whitespace() {
    while (this.index < this.text.length && /[\u0020\u0009\u000a\u000d]/.test(this.text[this.index])) {
      this.index++;
    }
  }

  validate() {
    this.whitespace();
    this.value();
    this.whitespace();
    if (this.index !== this.text.length) this.fail('unexpected trailing content');
  }

  value() {
    this.whitespace();
    const char = this.text[this.index];
    if (char === '"') {
      this.string();
      return;
    }
    if (char === '{') {
      this.object();
      return;
    }
    if (char === '[') {
      this.array();
      return;
    }
    for (const literal of ['true', 'false', 'null']) {
      if (this.text.startsWith(literal, this.index)) {
        this.index += literal.length;
        return;
      }
    }
    const match = /^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/.exec(this.text.slice(this.index));
    if (match) {
      const number = Number(match[0]);
      if (!Number.isFinite(number)) this.fail('number is outside the finite IEEE 754 range');
      this.index += match[0].length;
      return;
    }
    this.fail('expected a JSON value');
  }

  string() {
    const start = this.index++;
    while (this.index < this.text.length) {
      const code = this.text.charCodeAt(this.index);
      if (code === 0x22) {
        this.index++;
        let decoded;
        try {
          decoded = JSON.parse(this.text.slice(start, this.index));
        } catch {
          this.fail('invalid string escape or string syntax');
        }
        for (let i = 0; i < decoded.length; i++) {
          const unit = decoded.charCodeAt(i);
          if (unit >= 0xd800 && unit <= 0xdbff) {
            const next = decoded.charCodeAt(i + 1);
            if (!(next >= 0xdc00 && next <= 0xdfff)) this.fail('unpaired high surrogate');
            i++;
          } else if (unit >= 0xdc00 && unit <= 0xdfff) {
            this.fail('unpaired low surrogate');
          }
        }
        return decoded;
      }
      if (code < 0x20) this.fail('unescaped control character in string');
      if (code === 0x5c) {
        this.index += 2;
      } else {
        this.index++;
      }
    }
    this.fail('unterminated string');
  }

  object() {
    this.index++;
    this.whitespace();
    if (this.text[this.index] === '}') {
      this.index++;
      return;
    }
    const keys = new Set();
    while (true) {
      this.whitespace();
      if (this.text[this.index] !== '"') this.fail('expected an object key');
      const key = this.string();
      if (keys.has(key)) this.fail(`duplicate object key ${JSON.stringify(key)}`);
      keys.add(key);
      this.whitespace();
      if (this.text[this.index] !== ':') this.fail('expected colon after object key');
      this.index++;
      this.value();
      this.whitespace();
      if (this.text[this.index] === '}') {
        this.index++;
        return;
      }
      if (this.text[this.index] !== ',') this.fail('expected comma or closing brace');
      this.index++;
    }
  }

  array() {
    this.index++;
    this.whitespace();
    if (this.text[this.index] === ']') {
      this.index++;
      return;
    }
    while (true) {
      this.value();
      this.whitespace();
      if (this.text[this.index] === ']') {
        this.index++;
        return;
      }
      if (this.text[this.index] !== ',') this.fail('expected comma or closing bracket');
      this.index++;
    }
  }
}

function serialize(value) {
  if (value === null) return 'null';
  if (typeof value === 'string') return JSON.stringify(value);
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new Error('Cannot canonicalize a non-finite number');
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(serialize).join(',')}]`;
  if (typeof value === 'object') {
    const keys = Object.keys(value).sort();
    return `{${keys.map(key => `${JSON.stringify(key)}:${serialize(value[key])}`).join(',')}}`;
  }
  throw new Error(`Unsupported JSON value: ${typeof value}`);
}

export function canonicalizeJsonText(text) {
  new JsonValidator(text).validate();
  return serialize(JSON.parse(text));
}

function sha256(text) {
  return createHash('sha256').update(text, 'utf8').digest('hex');
}

async function readStdin() {
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  return Buffer.concat(chunks);
}

function decodeUtf8(bytes) {
  try {
    return new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
  } catch {
    throw new Error('input is not valid UTF-8');
  }
}

async function main() {
  const args = process.argv.slice(2);
  const hashOnly = args[0] === '--hash';
  if (hashOnly) args.shift();
  if (args.length > 1 || (args.length === 1 && args[0].startsWith('-'))) {
    throw new Error('usage: node molt-canonical.mjs [--hash] [file.json]');
  }
  const bytes = args.length === 1 ? await readFile(args[0]) : await readStdin();
  const canonical = canonicalizeJsonText(decodeUtf8(bytes));
  const hash = sha256(canonical);
  process.stdout.write(hashOnly ? `${hash}\n` : `${canonical}\nsha256: ${hash}\n`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch(error => {
    process.stderr.write(`molt-canonical: ${error.message}\n`);
    process.exitCode = 1;
  });
}
