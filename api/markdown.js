import { marked } from "marked";
import DOMPurify from "isomorphic-dompurify";

export default async function handler(req, res){
  res.setHeader("Content-Type","application/json; charset=utf-8");
  res.setHeader("Cache-Control","no-store");
  if (req.method !== "POST") return res.status(405).end();

  const body = (req.body || {}).body || "";
  const html = DOMPurify.sanitize(marked.parse(String(body), { mangle:false, headerIds:false }));
  res.json({ html });
}
