// Make fresh Ed25519 keys for this experiment, in protect-mcp's key file format
// (the same generation as `protect-mcp init`: 32 random bytes, noble ed25519).
// Files are written 0600 in a 0700 directory; only public keys are printed.
// Refuses to overwrite an existing key.
//
// Usage: node make_keys.mjs --gateway <gateway dir> --dir <keys dir> --names gate,harness
import { randomBytes } from 'node:crypto';
import { existsSync, mkdirSync, writeFileSync, chmodSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

function arg(name) {
  const i = process.argv.indexOf(name);
  return i >= 0 ? process.argv[i + 1] : undefined;
}
const gatewayDir = arg('--gateway');
const dir = arg('--dir');
const names = (arg('--names') || '').split(',').filter(Boolean);
const { ed25519 } = await import(pathToFileURL(join(gatewayDir, 'node_modules', '@noble', 'curves', 'ed25519.js')).href);
const hex = (b) => Buffer.from(b).toString('hex');

mkdirSync(dir, { recursive: true, mode: 0o700 });
chmodSync(dir, 0o700);
for (const name of names) {
  const path = join(dir, `${name}.json`);
  if (existsSync(path)) { process.stderr.write(`refusing to overwrite ${path}\n`); process.exit(1); }
  const priv = randomBytes(32);
  const pub = hex(ed25519.getPublicKey(priv));
  writeFileSync(path, JSON.stringify({
    privateKey: hex(priv), publicKey: pub, kid: `tau2-replay-${name}`, issuer: `tau2-replay-${name}`,
    generated_at: new Date().toISOString(), warning: 'Experiment key for the tau2 retail replay. Keep secret.',
  }, null, 2) + '\n', { mode: 0o600 });
  chmodSync(path, 0o600);
  writeFileSync(join(dir, `${name}.pub`), pub + '\n', { mode: 0o644 });
  process.stdout.write(`${name}: public ${pub}\n`);
}
