// Build/maintenance script for the private hub.
//   node _build.js unpack   -> decrypt every *.json into _src/<name>.html
//   node _build.js pack     -> encrypt every _src/<name>.html back into <name>.json
// Keeps sources in _src/ (gitignored) so the encrypted blobs stay the source of truth.
const { webcrypto } = require('crypto');
const subtle = webcrypto.subtle;
const fs = require('fs');
const path = require('path');

const PASSWORD = '7505brown';
const ITER = 200000;
const DIR = __dirname;
const SRC = path.join(DIR, '_src');
const TOOLS = ['calc', 'talk', 'notes', 'letter', 'plan', 'live'];

async function keyFor(salt, iters, usages) {
  const baseKey = await subtle.importKey('raw', new TextEncoder().encode(PASSWORD), 'PBKDF2', false, ['deriveKey']);
  return subtle.deriveKey({ name: 'PBKDF2', salt, iterations: iters, hash: 'SHA-256' },
    baseKey, { name: 'AES-GCM', length: 256 }, false, usages);
}
const b64 = u => Buffer.from(u).toString('base64');
const unb64 = s => Uint8Array.from(Buffer.from(s, 'base64'));

(async () => {
  const mode = process.argv[2];
  if (!fs.existsSync(SRC)) fs.mkdirSync(SRC);

  if (mode === 'unpack') {
    for (const t of TOOLS) {
      const f = path.join(DIR, t + '.json');
      if (!fs.existsSync(f)) { console.log(t.padEnd(7), 'no blob yet, skipping'); continue; }
      const p = JSON.parse(fs.readFileSync(f, 'utf8'));
      const key = await keyFor(unb64(p.s), p.n, ['decrypt']);
      const buf = await subtle.decrypt({ name: 'AES-GCM', iv: unb64(p.i) }, key, unb64(p.c));
      const html = new TextDecoder().decode(buf);
      fs.writeFileSync(path.join(SRC, t + '.html'), html);
      console.log(t.padEnd(7), '->', '_src/' + t + '.html', html.length, 'chars');
    }
    return;
  }

  if (mode === 'pack') {
    for (const t of TOOLS) {
      const f = path.join(SRC, t + '.html');
      if (!fs.existsSync(f)) { console.log(t.padEnd(7), 'no source, skipping'); continue; }
      const pt = fs.readFileSync(f, 'utf8');
      const salt = webcrypto.getRandomValues(new Uint8Array(16));
      const iv = webcrypto.getRandomValues(new Uint8Array(12));
      const key = await keyFor(salt, ITER, ['encrypt', 'decrypt']);
      const ct = await subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(pt));
      fs.writeFileSync(path.join(DIR, t + '.json'),
        JSON.stringify({ s: b64(salt), i: b64(iv), c: b64(new Uint8Array(ct)), n: ITER }));
      const back = new TextDecoder().decode(await subtle.decrypt({ name: 'AES-GCM', iv }, key, ct));
      const dashes = (pt.match(/[–—]/g) || []).length;
      console.log(t.padEnd(7), String(new Uint8Array(ct).length).padStart(7), 'bytes | roundtrip',
        back === pt ? 'PASS' : 'FAIL', '| dashes', dashes);
    }
    return;
  }

  console.log('usage: node _build.js [unpack|pack]');
})();
