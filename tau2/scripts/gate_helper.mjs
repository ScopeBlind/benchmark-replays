// Library-mode gate for the tau2 replay.
//
// Uses protect-mcp 0.32.2's own exported functions (loadCedarPolicies,
// evaluateCedar, initSigning, signDecision, receiptHash) and composes them the
// way `protect-mcp sign --cedar` does (src/cli.ts handleSign): the same
// decision entry, the same payload digest over the JCS bytes of the input,
// and the same chain link ("sha256:" + receiptHash of the previous receipt).
//
// Protocol: one JSON request per stdin line, one JSON reply per stdout line.
//   {"op":"pubkey"}
//   {"op":"decide","policy_dir":..,"tool":..,"input":{..},"prev":"sha256:.."|null}
//   {"op":"observe","tool":..,"input":{..},"prev":..}
//   {"op":"evaluate","policy_dir":..,"tool":..,"input":{..}}
//   {"op":"digest","policy_dir":..}
//   {"op":"parse","policy_dir":..}
// The private key never leaves this process; replies carry public material only.
//
// Usage: node gate_helper.mjs --gateway <gateway dir> --key <key file>
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { createInterface } from 'node:readline';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

function arg(name) {
  const i = process.argv.indexOf(name);
  return i >= 0 ? process.argv[i + 1] : undefined;
}

const gatewayDir = arg('--gateway');
const keyPath = arg('--key');
if (!gatewayDir) { process.stderr.write('need --gateway\n'); process.exit(2); }

const gw = await import(pathToFileURL(join(gatewayDir, 'dist', 'index.mjs')).href);
const { loadCedarPolicies, evaluateCedar, initSigning, signDecision, receiptHash } = gw;

let publicKey = null;
if (keyPath) {
  const warnings = await initSigning({ enabled: true, key_path: keyPath });
  if (warnings.length) { process.stderr.write(`signing warnings: ${warnings.join(' | ')}\n`); process.exit(3); }
  publicKey = JSON.parse(readFileSync(keyPath, 'utf-8')).publicKey;
}

const policyCache = new Map();
function policy(dir) {
  if (!policyCache.has(dir)) policyCache.set(dir, loadCedarPolicies(dir));
  return policyCache.get(dir);
}

// JCS for the inputs this replay produces (strings, integers, booleans, null,
// arrays, objects with ASCII keys). Checked against the gateway's own
// canonicalizer through receiptHash on every call.
function jcs(v) {
  if (v === null || typeof v !== 'object') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(jcs).join(',') + ']';
  const keys = Object.keys(v).sort();
  return '{' + keys.map((k) => JSON.stringify(k) + ':' + jcs(v[k])).join(',') + '}';
}

function payloadDigest(input) {
  const canonical = jcs(input);
  const hex = createHash('sha256').update(canonical, 'utf-8').digest('hex');
  const gwHex = receiptHash(input);
  if (hex !== gwHex) throw new Error('local JCS differs from the gateway canonicalizer');
  return { input_hash: hex, input_size: Buffer.byteLength(canonical, 'utf-8'), canonical: 'jcs' };
}

function requestId() {
  // the CLI's own form (src/cli.ts handleSign): tu-<ms>-<4 base36 chars>
  return `tu-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
}

function sign(entry, prev) {
  const res = signDecision(entry, prev || undefined);
  if (!res.ok || !res.signed) throw new Error(`signing failed: ${res.error || res.warning || 'unknown'}`);
  const link = 'sha256:' + receiptHash(JSON.parse(res.signed));
  return { receipt: res.signed, link };
}

async function handle(req) {
  switch (req.op) {
    case 'pubkey':
      return { public_key: publicKey };
    case 'digest':
      return { policy_digest: policy(req.policy_dir).digest, files: policy(req.policy_dir).files };
    case 'parse': {
      const set = policy(req.policy_dir);
      let engine;
      try { engine = await import(pathToFileURL(join(gatewayDir, 'node_modules', '@cedar-policy', 'cedar-wasm', 'nodejs', 'cedar_wasm.js')).href); }
      catch { engine = null; }
      const fn = engine && (engine.checkParsePolicySet || (engine.default && engine.default.checkParsePolicySet));
      if (!fn) return { checked: false, parse_ok: null };
      const ans = fn({ staticPolicies: set.source });
      return { checked: true, parse_ok: Boolean(ans && ans.type === 'success'), answer: ans && ans.type !== 'success' ? ans : undefined };
    }
    case 'evaluate': {
      const set = policy(req.policy_dir);
      const d = await evaluateCedar(set, { tool: req.tool, tier: 'unknown', context: {}, toolInput: req.input, actionModel: 'mcp' }, undefined, { failClosed: true });
      return { allowed: d.allowed, reason: d.reason || null, policy_digest: set.digest, matched: (d.metadata && (d.metadata.matched_policies || null)) || null, error: Boolean(d.metadata && d.metadata.error) };
    }
    case 'decide': {
      const set = policy(req.policy_dir);
      const d = await evaluateCedar(set, { tool: req.tool, tier: 'unknown', context: {}, toolInput: req.input, actionModel: 'mcp' }, undefined, { failClosed: true });
      const decision = d.allowed ? 'allow' : 'deny';
      const reason = d.allowed ? 'cedar_allow' : (d.reason || 'cedar_deny');
      const rid = requestId();
      const { receipt, link } = sign({
        tool: req.tool, decision, reason_code: reason, policy_digest: set.digest,
        request_id: rid, mode: 'enforce', timestamp: Date.now(), payload_digest: payloadDigest(req.input),
      }, req.prev);
      return {
        decision, reason, policy_digest: set.digest, request_id: rid, receipt, link,
        matched: (d.metadata && (d.metadata.matched_policies || null)) || null,
        error: Boolean(d.metadata && d.metadata.error),
      };
    }
    case 'observe': {
      const rid = requestId();
      const { receipt, link } = sign({
        tool: req.tool, decision: 'allow', reason_code: 'post_execution_receipt', policy_digest: 'none',
        request_id: rid, mode: 'enforce', timestamp: Date.now(), payload_digest: payloadDigest(req.input),
      }, req.prev);
      return { request_id: rid, receipt, link };
    }
    default:
      throw new Error(`unknown op ${req.op}`);
  }
}

const rl = createInterface({ input: process.stdin, crlfDelay: Infinity });
for await (const line of rl) {
  if (!line.trim()) continue;
  let reply;
  try {
    reply = { ok: true, ...(await handle(JSON.parse(line))) };
  } catch (err) {
    reply = { ok: false, error: err instanceof Error ? err.message : String(err) };
  }
  process.stdout.write(JSON.stringify(reply) + '\n');
}
