import crypto from "crypto";

const REDIS_URL = process.env.UPSTASH_REDIS_REST_URL;
const REDIS_TOKEN = process.env.UPSTASH_REDIS_REST_TOKEN;

async function redis(cmd, ...args){
  const r = await fetch(`${REDIS_URL}/${cmd}/${args.map(encodeURIComponent).join("/")}`,{
    headers:{ Authorization:`Bearer ${REDIS_TOKEN}` }
  });
  const j = await r.json();
  if (j.error) throw new Error(j.error);
  return j;
}

function json(res, obj){
  res.setHeader("Content-Type","application/json; charset=utf-8");
  res.setHeader("Cache-Control","no-store");
  res.end(JSON.stringify(obj));
}

function getSid(req){
  const c = String(req.headers.cookie||"");
  return (c.match(/(?:^|;\s*)sid=([^;]+)/)||[])[1]||"";
}

async function requireAuth(req, res){
  const sid = getSid(req);
  if (!sid) { res.statusCode=401; res.end(); return null; }
  const s = await redis("get",`sess:${sid}`);
  if (!s.result) { res.statusCode=401; res.end(); return null; }
  return s.result;
}

function esc(u){
  u = String(u||"").toLowerCase();
  if (u.startsWith("@")) u = u.slice(1);
  return u;
}

export default async function handler(req, res){
  const action = String(req.query.action||"");
  let body = {};
  if (req.method === "POST"){
    try {
      body = req.body || JSON.parse(await new Promise(r=>{
        let d=""; req.on("data",c=>d+=c); req.on("end",()=>r(d||"{}"));
      }));
    } catch {}
  }

  const email = await requireAuth(req,res);
  if (!email) return;

  // ===== CREATE POST =====
  if (action === "post_create"){
    if (!body.title || !body.body)
      return json(res,{ok:false,error:"EMPTY"});
    const me = JSON.parse((await redis("get",`user:email:${email}`)).result);
    const id = crypto.randomBytes(8).toString("hex");
    const post = {
      id,
      title: body.title.slice(0,120),
      body: body.body.slice(0,20_000),
      username: me.username,
      avatar: me.avatar||"",
      badges: me.badges||[],
      createdAt: Date.now()
    };
    await redis("set",`post:${id}`,JSON.stringify(post));
    await redis("lpush","posts",id);
    return json(res,{ok:true,id});
  }

  // ===== GET POSTS =====
  if (action === "posts_get"){
    const ids = (await redis("lrange","posts","0","40")).result||[];
    const out=[];
    for (const id of ids){
      const p = await redis("get",`post:${id}`);
      if (p.result) out.push(JSON.parse(p.result));
    }
    return json(res,{ok:true,posts:out});
  }

  // ===== SEARCH USERS =====
  if (action === "users_search"){
    const q = esc(req.query.q);
    const keys = (await redis("keys","user:username:*")).result||[];
    const users=[];
    for (const k of keys){
      const u = k.split(":").pop();
      if (u.includes(q)){
        const email = (await redis("get",k)).result;
        const user = JSON.parse((await redis("get",`user:email:${email}`)).result);
        users.push({ username:user.username, name:user.name, avatar:user.avatar });
        if (users.length>=20) break;
      }
    }
    return json(res,{ok:true,users});
  }

  res.statusCode=404;
  json(res,{ok:false,error:"UNKNOWN_ACTION"});
}
