import crypto from "crypto";
import { marked } from "marked";
import DOMPurify from "isomorphic-dompurify";

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

function sanitize(md){
  const html = marked.parse(String(md||""), { mangle:false, headerIds:false });
  return DOMPurify.sanitize(html);
}

export default async function handler(req, res){
  res.setHeader("Content-Type","application/json; charset=utf-8");
  res.setHeader("Cache-Control","no-store");

  if (req.method !== "POST") return res.status(405).end();

  const sid = getSid(req);
  if (!sid) return res.status(401).end();

  const se = await redis("get", `sess:${sid}`);
  if (!se.result) return res.status(401).end();
  const email = se.result;

  const { postId, body } = req.body || {};
  const pid = String(postId||"");
  const b = String(body||"").trim();
  if (!pid || !b) return res.status(400).json({ ok:false });
  if (b.length > 5000) return res.status(400).json({ ok:false });

  const cid = crypto.randomBytes(8).toString("hex");
  const html = sanitize(b);

  await redis("set", `comment:${pid}:${cid}`, JSON.stringify({
    id: cid,
    postId: pid,
    author: email,
    body: html,
    createdAt: Date.now()
  }));

  await redis("lpush", `comments:${pid}`, cid);
  res.json({ ok:true });
}
