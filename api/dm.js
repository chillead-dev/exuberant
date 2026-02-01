import crypto from "crypto";

const REDIS_URL = process.env.UPSTASH_REDIS_REST_URL;
const REDIS_TOKEN = process.env.UPSTASH_REDIS_REST_TOKEN;

async function redis(cmd, ...args){
  const url = `${REDIS_URL}/${cmd}/${args.map(encodeURIComponent).join("/")}`;
  const r = await fetch(url, { headers:{ Authorization:`Bearer ${REDIS_TOKEN}` }});
  const j = await r.json();
  if (j.error) throw new Error(`Redis error: ${j.error}`);
  return j;
}
function getSid(req){
  const c = String(req.headers.cookie || "");
  return (c.match(/(?:^|;\s*)sid=([^;]+)/) || [])[1] || "";
}
function normalizeUsername(u){
  u = String(u||"").trim().toLowerCase();
  if (u.startsWith("@")) u = u.slice(1);
  return u;
}
function threadIdFor(a, b){
  const x = [a,b].sort().join("|");
  return crypto.createHash("sha256").update(x).digest("hex").slice(0, 32);
}

export default async function handler(req, res){
  res.setHeader("Content-Type","application/json; charset=utf-8");
  res.setHeader("Cache-Control","no-store");

  // auth
  const sid = getSid(req);
  if (!sid) return res.status(401).end();
  const se = await redis("get", `sess:${sid}`);
  if (!se.result) return res.status(401).end();
  const myEmail = se.result;

  const action = String(req.query.action || "");

  // simple rate-limit
  const ip = (req.headers["x-forwarded-for"] || "").toString().split(",")[0].trim() || "ip";
  const rlKey = `rl:${ip}:dm`;
  const cur = await redis("incr", rlKey);
  if (cur.result === 1) await redis("expire", rlKey, "60");
  if (cur.result > 120) return res.status(429).json({ ok:false, error:"RATE_LIMIT" });

  // INIT: returns deterministic threadId
  if (action === "init"){
    const u = normalizeUsername(req.query.u);
    if (!u) return res.status(400).json({ ok:false, error:"BAD_USER" });

    const peerEmail = (await redis("get", `user:username:${u}`)).result;
    if (!peerEmail) return res.status(404).json({ ok:false, error:"NO_USER" });

    const threadId = threadIdFor(myEmail, peerEmail);

    // index threads per user (set)
    await redis("sadd", `dm:threads:${myEmail}`, threadId);
    await redis("sadd", `dm:threads:${peerEmail}`, threadId);

    return res.json({ ok:true, threadId });
  }

  // SEND: store ciphertext only
  if (action === "send" && req.method === "POST"){
    const body = req.body || {};
    const threadId = String(body.threadId || "");
    const nonce = String(body.nonce || "");
    const ciphertext = String(body.ciphertext || "");

    if (!threadId || threadId.length < 16) return res.status(400).json({ ok:false, error:"BAD_THREAD" });
    if (!nonce || !ciphertext) return res.status(400).json({ ok:false, error:"BAD_PAYLOAD" });
    if (ciphertext.length > 20000) return res.status(400).json({ ok:false, error:"TOO_LARGE" });

    // message id incremental
    const seq = await redis("incr", `dm:seq:${threadId}`);
    const id = Number(seq.result || 0);

    const msg = { id, from: myEmail, ts: Date.now(), nonce, ciphertext };
    await redis("set", `dm:msg:${threadId}:${id}`, JSON.stringify(msg));
    await redis("lpush", `dm:list:${threadId}`, String(id));
    // keep last N ids
    await redis("ltrim", `dm:list:${threadId}`, "0", "500");

    return res.json({ ok:true, id });
  }

  // FETCH: returns ciphertext messages after id
  if (action === "fetch" && req.method === "GET"){
    const threadId = String(req.query.threadId || "");
    const after = Number(req.query.after || 0);

    if (!threadId || threadId.length < 16) return res.status(400).json({ ok:false, error:"BAD_THREAD" });

    const idsResp = await redis("lrange", `dm:list:${threadId}`, "0", "80");
    const ids = (idsResp.result || []).map(x => Number(x)).filter(n => n > after).sort((a,b)=>a-b);

    const messages = [];
    for (const id of ids){
      const m = await redis("get", `dm:msg:${threadId}:${id}`);
      if (!m.result) continue;
      messages.push(JSON.parse(m.result));
    }

    return res.json({ ok:true, messages });
  }

  return res.status(404).json({ ok:false, error:"NOT_FOUND" });
}
