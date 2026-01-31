const REDIS_URL = process.env.UPSTASH_REDIS_REST_URL;
const REDIS_TOKEN = process.env.UPSTASH_REDIS_REST_TOKEN;

async function redis(cmd, ...args){
  const r = await fetch(`${REDIS_URL}/${cmd}/${args.map(encodeURIComponent).join("/")}`, {
    headers:{ Authorization:`Bearer ${REDIS_TOKEN}` }
  });
  const j = await r.json();
  if (j.error) throw new Error(`Redis error: ${j.error}`);
  return j;
}

function getSid(req){
  const c = String(req.headers.cookie || "");
  return (c.match(/(?:^|;\s*)sid=([^;]+)/) || [])[1] || "";
}

async function authorTagByEmail(email){
  const u = await redis("get", `user:email:${email}`);
  if (!u.result) return email;
  const user = JSON.parse(u.result);
  return "@"+(user.username||"");
}

export default async function handler(req, res){
  res.setHeader("Content-Type","application/json; charset=utf-8");
  res.setHeader("Cache-Control","no-store");

  const sid = getSid(req);
  if (!sid) return res.status(401).end();

  const se = await redis("get", `sess:${sid}`);
  if (!se.result) return res.status(401).end();

  const id = String(req.query.id || "");
  if (!id) return res.status(400).json({ error:"BAD_ID" });

  const p = await redis("get", `post:${id}`);
  if (!p.result) return res.status(404).json({ error:"NOT_FOUND" });

  const post = JSON.parse(p.result);
  post.authorTag = await authorTagByEmail(post.author);

  const cl = await redis("lrange", `comments:${id}`, 0, 100);
  const comments = [];
  for (const cid of (cl.result || [])){
    const c = await redis("get", `comment:${id}:${cid}`);
    if (!c.result) continue;
    const obj = JSON.parse(c.result);
    obj.authorTag = await authorTagByEmail(obj.author);
    comments.push(obj);
  }

  res.json({ post, comments });
}
