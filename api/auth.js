import crypto from "crypto";

const REDIS_URL = process.env.UPSTASH_REDIS_REST_URL;
const REDIS_TOKEN = process.env.UPSTASH_REDIS_REST_TOKEN;
const RESEND_KEY = process.env.RESEND_API_KEY;
const AUTH_SECRET = process.env.AUTH_SECRET;

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

function setSid(res, sid){
  res.setHeader("Set-Cookie",
    `sid=${sid}; Path=/; HttpOnly; SameSite=Lax; Secure; Max-Age=${60*60*24*30}`
  );
}

function clearSid(res){
  res.setHeader("Set-Cookie",
    `sid=; Path=/; HttpOnly; SameSite=Lax; Secure; Max-Age=0`
  );
}

async function requireAuth(req, res){
  const sid = getSid(req);
  if (!sid) { res.statusCode=401; res.end(); return null; }
  const s = await redis("get",`sess:${sid}`);
  if (!s.result) { res.statusCode=401; res.end(); return null; }
  return s.result;
}

function hash(p){
  return crypto.createHmac("sha256", AUTH_SECRET).update(p).digest("hex");
}

function normEmail(e){ return String(e||"").trim().toLowerCase(); }
function normUser(u){
  u = String(u||"").trim().toLowerCase();
  if (u.startsWith("@")) u = u.slice(1);
  return u;
}

async function sendMail(to, code){
  await fetch("https://api.resend.com/emails",{
    method:"POST",
    headers:{
      Authorization:`Bearer ${RESEND_KEY}`,
      "Content-Type":"application/json"
    },
    body: JSON.stringify({
      from: "Exuberant <auth@exuberant.pw>",
      to,
      subject: "Your login code",
      html: `<b>${code}</b><p>Valid 5 minutes</p>`
    })
  });
}

export default async function handler(req, res){
  const action = String(req.query.action||"");
  let body = {};
  if (req.method === "POST") {
    try {
      body = req.body || JSON.parse(await new Promise(r=>{
        let d=""; req.on("data",c=>d+=c); req.on("end",()=>r(d||"{}"));
      }));
    } catch {}
  }

  // ===== REGISTER SEND CODE =====
  if (action === "register_send"){
    const email = normEmail(body.email);
    if (!email.includes("@")) return json(res,{ok:false,error:"BAD_EMAIL"});
    if (await redis("get",`user:email:${email}`).then(r=>r.result))
      return json(res,{ok:false,error:"ACCOUNT_EXISTS"});

    const code = Math.floor(100000+Math.random()*900000).toString();
    await redis("set",`pending:${email}`,JSON.stringify({
      code,
      pw: hash(body.password||"")
    }),"EX",300);

    await sendMail(email, code);
    return json(res,{ok:true});
  }

  // ===== REGISTER VERIFY =====
  if (action === "register_verify"){
    const email = normEmail(body.email);
    const p = await redis("get",`pending:${email}`);
    if (!p.result) return json(res,{ok:false,error:"NO_PENDING"});
    if (JSON.parse(p.result).code !== body.code)
      return json(res,{ok:false,error:"BAD_CODE"});
    await redis("set",`pending:${email}`,JSON.stringify({
      ...JSON.parse(p.result), ok:true
    }),"EX",600);
    return json(res,{ok:true});
  }

  // ===== REGISTER SETUP =====
  if (action === "register_setup"){
    const email = normEmail(body.email);
    const u = normUser(body.username);
    const p = await redis("get",`pending:${email}`);
    if (!p.result || !JSON.parse(p.result).ok)
      return json(res,{ok:false,error:"NO_VERIFY"});
    if (await redis("get",`user:username:${u}`).then(r=>r.result))
      return json(res,{ok:false,error:"USERNAME_TAKEN"});

    const data = JSON.parse(p.result);
    const user = {
      email,
      username: u,
      name: body.name||"",
      pw: data.pw,
      avatar:"",
      about:"",
      badges:[]
    };

    await redis("set",`user:email:${email}`,JSON.stringify(user));
    await redis("set",`user:username:${u}`,email);
    await redis("del",`pending:${email}`);

    const sid = crypto.randomBytes(24).toString("hex");
    await redis("set",`sess:${sid}`,email,"EX",60*60*24*30);
    setSid(res,sid);
    return json(res,{ok:true});
  }

  // ===== LOGIN =====
  if (action === "login"){
    const email = normEmail(body.email);
    const u = await redis("get",`user:email:${email}`);
    if (!u.result) return json(res,{ok:false,error:"NO_ACCOUNT"});
    if (JSON.parse(u.result).pw !== hash(body.password||""))
      return json(res,{ok:false,error:"BAD_LOGIN"});

    const sid = crypto.randomBytes(24).toString("hex");
    await redis("set",`sess:${sid}`,email,"EX",60*60*24*30);
    setSid(res,sid);
    return json(res,{ok:true});
  }

  // ===== PROFILE GET =====
  if (action === "profile_get"){
    const email = await requireAuth(req,res);
    if (!email) return;
    const u = JSON.parse((await redis("get",`user:email:${email}`)).result);
    return json(res,{ok:true,user:u});
  }

  // ===== PROFILE UPDATE =====
  if (action === "profile_set"){
    const email = await requireAuth(req,res);
    if (!email) return;
    const u = JSON.parse((await redis("get",`user:email:${email}`)).result);
    if (body.name!==undefined) u.name = String(body.name).slice(0,40);
    if (body.about!==undefined) u.about = String(body.about).slice(0,240);
    if (Array.isArray(body.badges)) u.badges = body.badges.slice(0,5);
    await redis("set",`user:email:${email}`,JSON.stringify(u));
    return json(res,{ok:true});
  }

  // ===== AVATAR SET =====
  if (action === "avatar_set"){
    const email = await requireAuth(req,res);
    if (!email) return;
    if (!String(body.dataUrl||"").startsWith("data:image/"))
      return json(res,{ok:false,error:"BAD_IMAGE"});
    const u = JSON.parse((await redis("get",`user:email:${email}`)).result);
    u.avatar = body.dataUrl.slice(0,2_000_000);
    await redis("set",`user:email:${email}`,JSON.stringify(u));
    return json(res,{ok:true});
  }

  // ===== LOGOUT =====
  if (action === "logout"){
    clearSid(res);
    return json(res,{ok:true});
  }

  res.statusCode=404;
  json(res,{ok:false,error:"UNKNOWN_ACTION"});
}
