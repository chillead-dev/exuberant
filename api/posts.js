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

async function requireAuth(req, res){
  const sid = getSid(req);
  if (!sid) { res.statusCode = 401; res.end(); return null; }
  const se = await redis("get", `sess:${sid}`);
  if (!se.result) { res.statusCode = 401; res.end(); return null; }
  return se.result; // email
}

function snippetFrom(body){
  const t = String(body||"").replace(/\s+/g," ").trim();
  return t.slice(0, 180);
}

export default async function handler(req, res){
  res.setHeader("Content-Type","application/json; charset=utf-8");
  res.setHeader("Cache-Control","no-store");

  const email = await requireAuth(req, res);
  if (!email) return;

  if (req.method === "POST"){
    const body = req.body || {};
    const title = String(body.title||"").trim();
    const text = String(body.body||"").trim();

    if (title.length < 3) return res.end(JSON.stringify({ ok:false, error:"Title too short" }));
    if (text.length < 10) return res.end(JSON.stringify({ ok:false, error:"Body too short" }));
    if (text.length > 20000) return res.end(JSON.stringify({ ok:false, error:"Body too large" }));

    const meRaw = (await redis("get", `user:email:${email}`)).result;
    if (!meRaw) return res.end(JSON.stringify({ ok:false, error:"NO_PROFILE" }));
    const me = JSON.parse(meRaw);

    const id = crypto.randomBytes(8).toString("hex");
    const post = {
      id,
      title,
      body: text,
      snippet: snippetFrom(text),
      authorEmail: email,
      username: me.username,
      avatar: me.avatar || "",
      badges: me.badges || [],
      createdAt: Date.now()
    };

    await redis("set", `post:${id}`, JSON.stringify(post));
    await redis("lpush", "posts", id);
    await redis("ltrim", "posts", "0", "300");

    return res.end(JSON.stringify({ ok:true, id }));
  }

  if (req.method === "GET"){
    const author = String(req.query.author || "").trim().toLowerCase();
    const ids = (await redis("lrange", "posts", "0", "40")).result || [];

    const out = [];
    for (const id of ids){
      const p = await redis("get", `post:${id}`);
      if (!p.result) continue;
      const post = JSON.parse(p.result);

      if (author && String(post.username||"").toLowerCase() !== author) continue;
      out.push(post);
    }
    return res.end(JSON.stringify({ ok:true, posts: out }));
  }

  res.statusCode = 405;
  res.end(JSON.stringify({ ok:false, error:"METHOD_NOT_ALLOWED" }));
}
