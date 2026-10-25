// Recompute every sampled receipt from its published parts (design 4.6, PF7).
// Usage: node recompute.mjs <gateway_dist_index_mjs> <out_root> <expected_public_key_hex>
// For each line of bundle/items.jsonl and the matching receipt:
//  - sha256 over an independent JCS (RFC 8785) of the published input equals
//    payload.payload_digest.input_hash, and its byte length equals input_size;
//  - re-evaluating (policy files, input, facts) with the library gives the
//    signed decision, the signed reason and the signed policy digest;
//  - tool name, public key and kid are as expected.
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { join } from 'node:path';

const [, , gwPath, root, pub] = process.argv;
const { loadCedarPolicies, evaluateCedar } = await import(gwPath);

function jcs(v) {
  if (v === null || typeof v !== 'object') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(jcs).join(',') + ']';
  return '{' + Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + jcs(v[k])).join(',') + '}';
}

const items = readFileSync(join(root, 'bundle', 'items.jsonl'), 'utf-8').trim().split('\n').map((l) => JSON.parse(l));
const receipts = readFileSync(join(root, 'bundle', 'receipts', 'receipts.jsonl'), 'utf-8').trim().split('\n').map((l) => JSON.parse(l));
const sets = {};
const out = { n: items.length, input_hash_match: 0, input_size_match: 0, decision_match: 0, reason_match: 0, digest_match: 0,
  tool_match: 0, public_key_match: 0, kid: {}, mismatches: [] };
for (const it of items) {
  const rec = receipts[it.receipt_line - 1];
  const p = rec.payload;
  const canon = jcs(it.input);
  const h = createHash('sha256').update(canon, 'utf-8').digest('hex');
  const okHash = p.payload_digest && p.payload_digest.input_hash === h;
  const okSize = p.payload_digest && p.payload_digest.input_size === Buffer.byteLength(canon, 'utf-8');
  sets[it.policy_dir] ??= loadCedarPolicies(join(root, it.policy_dir));
  const d = await evaluateCedar(sets[it.policy_dir], { tool: it.tool, tier: 'unknown', context: it.facts, toolInput: it.input, actionModel: 'mcp' }, undefined, { failClosed: true });
  const dec = d.allowed ? 'allow' : 'deny';
  const reason = d.allowed ? 'cedar_allow' : d.reason;
  const okDec = dec === p.decision;
  const okReason = reason === p.reason;
  const okDigest = sets[it.policy_dir].digest === p.policy_digest;
  const okTool = p.tool_name === it.tool;
  const okPub = p.public_key === pub;
  out.input_hash_match += okHash; out.input_size_match += okSize; out.decision_match += okDec; out.reason_match += okReason;
  out.digest_match += okDigest; out.tool_match += okTool; out.public_key_match += okPub;
  const kid = rec.signature && rec.signature.kid; out.kid[kid] = (out.kid[kid] || 0) + 1;
  if (!(okHash && okSize && okDec && okReason && okDigest && okTool && okPub)) {
    out.mismatches.push({ line: it.receipt_line, okHash, okSize, okDec, okReason, okDigest, okTool, okPub });
  }
}
console.log(JSON.stringify(out, null, 1));
