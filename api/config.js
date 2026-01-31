export default async function handler(req, res){
  res.setHeader("Content-Type","application/json; charset=utf-8");
  res.setHeader("Cache-Control","no-store");
  res.json({ turnstileSiteKey: process.env.TURNSTILE_SITE_KEY || "" });
}
