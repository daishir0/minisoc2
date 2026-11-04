// Parse the Ubuntu USN database (decompressed JSON) into a compact per-release map and print it as
// JSON on stdout. Run in a short-lived child process with a large heap so the long-lived worker never
// holds the ~355 MB parse in its own memory.
//
//   node --max-old-space-size=4096 usn-parse.mjs <database.json> <release1,release2,...>
//
// Output: { "<release>": { "<CVE-...>": { "<source-pkg>": "<fixed-version>" } } }
// Only "released" fixes exist in the USN DB (each USN ships a fixed version per release/source).
import { readFileSync } from 'node:fs';

const jsonPath = process.argv[2];
const releases = (process.argv[3] || '').split(',').map((s) => s.trim()).filter(Boolean);
if (!jsonPath || !releases.length) {
  console.error('usage: usn-parse.mjs <database.json> <release1,release2,...>');
  process.exit(2);
}

const db = JSON.parse(readFileSync(jsonPath, 'utf8'));
/** @type {Record<string, Record<string, Record<string, string>>>} */
const out = {};
for (const rel of releases) out[rel] = {};

for (const uid of Object.keys(db)) {
  const entry = db[uid];
  const cves = Array.isArray(entry?.cves) ? entry.cves.filter((c) => /^CVE-\d{4}-\d+$/.test(c)) : [];
  if (!cves.length) continue;
  const rels = entry.releases || {};
  for (const rel of releases) {
    const r = rels[rel];
    const sources = r?.sources;
    if (!sources) continue;
    const relOut = out[rel];
    for (const cve of cves) {
      let m = relOut[cve];
      if (!m) { m = {}; relOut[cve] = m; }
      for (const [src, info] of Object.entries(sources)) {
        const v = info?.version;
        if (v) m[src] = v; // last USN (highest/newest) wins when a source appears in several USNs
      }
    }
  }
}

process.stdout.write(JSON.stringify(out));
