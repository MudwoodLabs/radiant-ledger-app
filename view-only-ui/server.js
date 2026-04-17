#!/usr/bin/env node
/**
 * Tiny HTTP proxy that lets the browser-based classifier fetch a tx by ID.
 *
 * Browsers can't open raw TCP/SSL to ElectrumX, so we bridge via the Radiant
 * full node sitting in the `radiant-mainnet` Docker container on the VPS.
 *
 *   GET /tx/<txid>   →  { txid, vout:[...] }     via `radiant-cli getrawtransaction <txid> 1`
 *   GET /height      →  { height: N }            via `getblockcount`
 *
 * Usage (from a machine with ssh access to the VPS):
 *   node server.js                        # listens on 127.0.0.1:3999
 *   PORT=4000 VPS=root@1.2.3.4 node server.js
 *
 * Then point the UI's "Fetch endpoint" at `http://localhost:3999/tx/`.
 * Zero npm deps — uses only Node stdlib.
 */

const http = require("node:http");
const { spawn } = require("node:child_process");

const PORT = process.env.PORT || 3999;
const VPS = process.env.VPS || "user@your-vps-ip";
const CLI = "docker exec radiant-mainnet radiant-cli -datadir=/home/radiant/.radiant";

/**
 * Run radiant-cli on the VPS via ssh. Passes the full remote command as a
 * single argv element so the local Node shell never sees it — only the VPS's
 * shell parses the quoting, which avoids the double-escape mess that breaks
 * JSON args (parentheses, brackets, single quotes) to scantxoutset.
 */
// Hard cap on upstream RPC output so a compromised or misbehaving node can't
// pipe arbitrary bytes into our memory. getblock v2 on a fat block is ~10 MB
// max on Radiant mainnet; 50 MB leaves headroom without risking OOM.
const MAX_RPC_BYTES = 50 * 1024 * 1024;

function rpc(remoteCmd) {
  return new Promise((resolve, reject) => {
    const p = spawn("ssh", [VPS, `${CLI} ${remoteCmd}`], { stdio: ["ignore", "pipe", "pipe"] });
    const chunks = [], errChunks = [];
    let total = 0;
    let killed = false;
    p.stdout.on("data", c => {
      total += c.length;
      if (total > MAX_RPC_BYTES && !killed) {
        killed = true;
        p.kill("SIGKILL");
        reject(new Error(`radiant-cli response exceeded ${MAX_RPC_BYTES} bytes`));
        return;
      }
      chunks.push(c);
    });
    p.stderr.on("data", c => errChunks.push(c));
    p.on("error", reject);
    p.on("close", code => {
      if (killed) return;
      if (code === 0) return resolve(Buffer.concat(chunks).toString("utf8").trim());
      const stderr = Buffer.concat(errChunks).toString("utf8").trim();
      reject(new Error(`radiant-cli exit=${code}: ${stderr || "no stderr"}`));
    });
  });
}

const isTxid = s => /^[0-9a-f]{64}$/i.test(s);

const isAddr = s => /^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$/.test(s);
const isRef  = s => /^[0-9a-fA-F]{72}$/.test(s);

// In-memory cache: ref_hex → { reveal_tx, commit_txid, commit_vout, blocks_scanned }
// Cache is capped at REVEAL_CACHE_MAX entries (LRU-ish: clears when full).
const revealCache = new Map();
const REVEAL_CACHE_MAX = 256;

// Concurrency gate: /reveal spawns up to 30 sequential RPC calls per request.
// Without a cap, a client that opens many cards at once can OOM the Node proxy.
let revealInFlight = 0;
const REVEAL_MAX_IN_FLIGHT = 3;

/**
 * Given a 36-byte ref (= reversed commit_txid ‖ commit_vout_LE), locate the
 * reveal tx — the tx that spent commit_tx:commit_vout and embeds the CBOR
 * payload in its vin[0].scriptSig.
 *
 * Scans up to 30 blocks forward from the commit block's height. Radiant's
 * standard glyph mints put reveal in the same block or the next one or two,
 * so this almost always finds it in ≤2 block reads.
 */
// Cache entries expire after CACHE_TTL_MS. This protects against chain reorgs
// where a reveal tx gets orphaned and a new tx re-reveals the same commit with
// different CBOR metadata. Without TTL the UI would show stale metadata
// indefinitely. 10 minutes is much longer than typical reorg depth.
const CACHE_TTL_MS = 10 * 60 * 1000;

async function findReveal(refHex) {
  const cached = revealCache.get(refHex);
  if (cached && (Date.now() - cached.cached_at_ms) < CACHE_TTL_MS) {
    return cached;
  }
  if (cached) revealCache.delete(refHex);  // expired
  if (revealInFlight >= REVEAL_MAX_IN_FLIGHT) {
    throw new Error("too many concurrent reveal lookups; retry in a few seconds");
  }
  revealInFlight++;
  try {
    return await findRevealInner(refHex);
  } finally {
    revealInFlight--;
  }
}

async function findRevealInner(refHex) {
  const commitTxidRev = refHex.slice(0, 64);
  const commitTxid = Buffer.from(commitTxidRev, "hex").reverse().toString("hex");
  const commitVoutHex = refHex.slice(64, 72);
  const commitVout = parseInt(
    commitVoutHex.slice(6, 8) + commitVoutHex.slice(4, 6) +
    commitVoutHex.slice(2, 4) + commitVoutHex.slice(0, 2),
    16
  );

  const commitTx = JSON.parse(await rpc(`getrawtransaction ${commitTxid} 1`));
  if (!commitTx.blockhash) throw new Error("commit tx not yet confirmed");
  const header = JSON.parse(await rpc(`getblockheader ${commitTx.blockhash}`));

  const maxLookahead = 30;
  for (let i = 0; i < maxLookahead; i++) {
    const height = header.height + i;
    const blockHash = (await rpc(`getblockhash ${height}`)).trim();
    const block = JSON.parse(await rpc(`getblock ${blockHash} 2`));
    for (const tx of block.tx || []) {
      if (tx.txid === commitTxid) continue;
      for (const vin of tx.vin || []) {
        if (vin.txid === commitTxid && vin.vout === commitVout) {
          const result = {
            reveal_tx: tx,
            commit_txid: commitTxid,
            commit_vout: commitVout,
            commit_block_height: header.height,
            reveal_block_height: height,
            blocks_scanned: i + 1,
            cached_at_ms: Date.now(),
          };
          revealCache.set(refHex, result);
          return result;
        }
      }
    }
  }
  throw new Error(`no reveal tx found in ${maxLookahead} blocks from commit height ${header.height}`);
}

http.createServer(async (req, res) => {
  const allowedOrigin = req.headers.origin || "http://localhost:8788";
  res.setHeader("Access-Control-Allow-Origin", /^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(allowedOrigin) ? allowedOrigin : "http://localhost:8788");
  res.setHeader("Content-Type", "application/json");
  try {
    if (req.url === "/height") {
      res.end(JSON.stringify({ height: parseInt(await rpc("getblockcount"), 10) }));
      return;
    }
    const txMatch = req.url.match(/^\/tx\/([0-9a-fA-F]{64})\/?$/);
    if (txMatch && isTxid(txMatch[1])) {
      const requested = txMatch[1].toLowerCase();
      const rawJson = await rpc(`getrawtransaction ${requested} 1`);
      // Round-trip check: a compromised node could return tx data for a
      // different txid than requested (e.g. to trick the UI into rendering
      // attacker metadata under a legitimate txid). Parse + verify before
      // forwarding to the browser. If the node lies, the anomaly is
      // surfaced loudly.
      try {
        const tx = JSON.parse(rawJson);
        const returned = String(tx.txid || "").toLowerCase();
        if (returned !== requested) {
          console.error(`txid mismatch: requested ${requested}, node returned ${returned}`);
          res.statusCode = 502;
          res.end(JSON.stringify({ error: "upstream node returned tx with different txid than requested" }));
          return;
        }
      } catch (e) {
        res.statusCode = 502;
        res.end(JSON.stringify({ error: "upstream returned unparseable JSON" }));
        return;
      }
      res.end(rawJson);
      return;
    }
    // Plain-P2PKH UTXO scan for a Radiant address (read-only, uses scantxoutset)
    const addrMatch = req.url.match(/^\/scan\/addr\/([a-zA-Z0-9]+)\/?$/);
    if (addrMatch && isAddr(addrMatch[1])) {
      const addr = addrMatch[1];
      const scanArg = `'["addr(${addr})"]'`;
      res.end(await rpc(`scantxoutset start ${scanArg}`));
      return;
    }
    // Raw-descriptor UTXO scan — lets caller query specific 75B FT or 63B NFT bytes.
    const rawMatch = req.url.match(/^\/scan\/raw\/([0-9a-fA-F]+)\/?$/);
    if (rawMatch) {
      const desc = rawMatch[1].toLowerCase();
      if (desc.length < 2 || desc.length > 400) {
        res.statusCode = 400;
        res.end(JSON.stringify({ error: "raw scan descriptor must be 1-200 bytes hex" }));
        return;
      }
      const scanArg = `'["raw(${desc})"]'`;
      res.end(await rpc(`scantxoutset start ${scanArg}`));
      return;
    }
    // Multi-descriptor scan: POST { descriptors: ["addr(X)", "raw(Y)", ...] }
    // Returns one unified unspents list — the client uses classify() to attribute each UTXO.
    if (req.url === "/scan/multi" && req.method === "POST") {
      const chunks = [];
      let bodyLen = 0;
      const MAX_BODY = 65536;
      for await (const chunk of req) {
        bodyLen += chunk.length;
        if (bodyLen > MAX_BODY) { res.statusCode = 413; res.end(JSON.stringify({ error: "body too large (max 64 KB)" })); return; }
        chunks.push(chunk);
      }
      const body = Buffer.concat(chunks).toString("utf8");
      let descriptors;
      try {
        const parsed = JSON.parse(body);
        descriptors = parsed.descriptors;
      } catch {
        res.statusCode = 400;
        res.end(JSON.stringify({ error: "body must be JSON { descriptors: [...] }" }));
        return;
      }
      if (!Array.isArray(descriptors) || descriptors.length === 0 || descriptors.length > 32) {
        res.statusCode = 400;
        res.end(JSON.stringify({ error: "descriptors must be a non-empty array of <= 32 strings" }));
        return;
      }
      for (const d of descriptors) {
        if (typeof d !== "string" || !/^(addr|raw)\([0-9a-zA-Z]+\)$/.test(d)) {
          res.statusCode = 400;
          res.end(JSON.stringify({ error: `rejected descriptor: ${d}` }));
          return;
        }
      }
      const jsonArr = descriptors.map(d => JSON.stringify(d)).join(",");
      res.end(await rpc(`scantxoutset start '[${jsonArr}]'`));
      return;
    }
    // Find reveal tx given a 36-byte ref (NFT singleton or FT mint)
    const revealMatch = req.url.match(/^\/reveal\/([0-9a-fA-F]{72})\/?$/);
    if (revealMatch && isRef(revealMatch[1])) {
      const result = await findReveal(revealMatch[1].toLowerCase());
      res.end(JSON.stringify(result));
      return;
    }
    // IPFS image proxy — keeps user's IP off third-party gateways.
    const ipfsMatch = req.url.match(/^\/ipfs\/([a-zA-Z0-9]+)\/?$/);
    if (ipfsMatch) {
      const cid = ipfsMatch[1];
      if (!/^(Qm[1-9A-Za-z]{44,}|bafy[a-z2-7]{50,})$/.test(cid)) {
        res.statusCode = 400;
        res.end(JSON.stringify({ error: "invalid IPFS CID" }));
        return;
      }
      const https = require("node:https");
      const MAX_BYTES = 4 * 1024 * 1024; // 4 MB cap — typical NFT thumbnails are well under this
      const upstream = `https://ipfs.io/ipfs/${cid}`;
      https.get(upstream, { timeout: 30000 }, (proxyRes) => {
        // Force a safe Content-Type. We never echo upstream's because a malicious IPFS pin
        // could set `text/html` and achieve code execution in the `localhost:3999` origin.
        // The browser will sniff the bytes and display via <img> correctly regardless.
        res.writeHead(proxyRes.statusCode, {
          "Content-Type": "application/octet-stream",
          "X-Content-Type-Options": "nosniff",
          "Content-Security-Policy": "default-src 'none'",
          "Cache-Control": "public, max-age=86400",
        });
        let sent = 0;
        proxyRes.on("data", chunk => {
          sent += chunk.length;
          if (sent > MAX_BYTES) {
            proxyRes.destroy();
            res.end();
          } else {
            res.write(chunk);
          }
        });
        proxyRes.on("end", () => res.end());
      }).on("error", (e) => {
        console.error("IPFS proxy error:", e.message);
        res.statusCode = 502;
        res.end(JSON.stringify({ error: "IPFS gateway unreachable" }));
      });
      return;
    }
    // CORS preflight
    if (req.method === "OPTIONS") {
      res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
      res.setHeader("Access-Control-Allow-Headers", "Content-Type");
      res.statusCode = 204;
      res.end();
      return;
    }
    res.statusCode = 404;
    res.end(JSON.stringify({ error: "routes: GET /tx/<txid>, GET /reveal/<ref_hex>, GET /ipfs/<cid>, GET /scan/addr/<address>, GET /scan/raw/<spk_hex>, POST /scan/multi, GET /height" }));
  } catch (e) {
    console.error("RPC error:", e.message || e);
    res.statusCode = 500;
    res.end(JSON.stringify({ error: "internal server error" }));
  }
}).listen(PORT, "127.0.0.1", () => {
  console.log(`radiant tx proxy listening on http://127.0.0.1:${PORT}`);
  console.log(`  GET  /tx/<txid>            →  getrawtransaction <txid> 1`);
  console.log(`  GET  /reveal/<ref_hex>     →  locate reveal tx for a glyph ref (for metadata)`);
  console.log(`  GET  /ipfs/<cid>           →  proxy IPFS image fetch (no IP leak to gateway)`);
  console.log(`  GET  /scan/addr/<address>  →  scantxoutset start [addr(<address>)]`);
  console.log(`  GET  /scan/raw/<spk_hex>   →  scantxoutset start [raw(<hex>)]`);
  console.log(`  POST /scan/multi           →  scantxoutset start [<descriptors...>]`);
  console.log(`  GET  /height               →  getblockcount`);
  console.log(`bridging to ${VPS} via ssh`);
});
