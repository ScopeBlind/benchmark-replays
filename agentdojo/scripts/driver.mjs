// Replay driver: evaluate every adapted call under both policy variants with
// the protect-mcp library (the same evaluateCedar the CLI's evaluate and
// sign --cedar call). Usage:
//   node driver.mjs <gateway_dist_index_mjs> <policies_dir> <calls.jsonl.gz> <decisions.jsonl.gz> [limit]
// Output, one line per (call, variant):
//   {"t":trace,"i":call,"v":"A"|"full","a":allowed,"c":"allow"|"deny"|"error","r":rule ids or error reason}
// The driver sees only suite, tool, args and facts. It never reads trace
// files, labels, task ids or the scorer.
import { createReadStream, createWriteStream } from 'node:fs';
import { createGunzip, createGzip } from 'node:zlib';
import { once } from 'node:events';
import { join } from 'node:path';
import readline from 'node:readline';

const [, , gwPath, polDir, callsPath, outPath, limitArg] = process.argv;
const limit = limitArg ? Number(limitArg) : Infinity;
const { loadCedarPolicies, evaluateCedar } = await import(gwPath);

const SUITES = ['banking', 'slack', 'travel', 'workspace'];
const VARIANTS = ['A', 'full'];
const sets = {};
for (const s of SUITES) {
  sets[s] = {};
  for (const v of VARIANTS) sets[s][v] = loadCedarPolicies(join(polDir, s, v));
}

const gz = createGzip({ level: 6 });
const sink = createWriteStream(outPath);
gz.pipe(sink);
const write = async (line) => { if (!gz.write(line + '\n')) await once(gz, 'drain'); };

const counts = {};
const bump = (k) => { counts[k] = (counts[k] || 0) + 1; };
const rl = readline.createInterface({ input: createReadStream(callsPath).pipe(createGunzip()), crlfDelay: Infinity });
const t0 = process.hrtime.bigint();
let n = 0;
let evals = 0;
for await (const line of rl) {
  if (!line) continue;
  if (n >= limit) break;
  const c = JSON.parse(line);
  for (const v of VARIANTS) {
    const d = await evaluateCedar(sets[c.suite][v], { tool: c.tool, tier: 'unknown', context: c.facts, toolInput: c.args, actionModel: 'mcp' }, undefined, { failClosed: true });
    evals++;
    const reason = d.reason || '';
    const cls = d.allowed ? 'allow' : (reason.startsWith('cedar_deny') ? 'deny' : 'error');
    const r = cls === 'deny'
      ? ((d.metadata && Array.isArray(d.metadata.denied_by)) ? d.metadata.denied_by.map((x) => x.id).join('+') : 'unnamed')
      : (cls === 'error' ? reason.slice(0, 300) : '');
    bump(`${c.suite}|${v}|${cls}`);
    await write(JSON.stringify({ t: c.t, i: c.i, v, a: d.allowed, c: cls, r }));
  }
  n++;
}
gz.end();
await once(sink, 'finish');
const secs = Number(process.hrtime.bigint() - t0) / 1e9;
const digests = Object.fromEntries(SUITES.map((s) => [s, Object.fromEntries(VARIANTS.map((v) => [v, sets[s][v].digest]))]));
console.log(JSON.stringify({ calls: n, evaluations: evals, seconds: Number(secs.toFixed(2)), per_eval_ms: Number((secs * 1000 / Math.max(evals, 1)).toFixed(4)), counts, digests }, null, 1));
