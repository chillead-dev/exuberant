import crypto from "crypto";

const REDIS_URL = process.env.UPSTASH_REDIS_REST_URL;
const REDIS_TOKEN = process.env.UPSTASH_REDIS_REST_TOKEN;
const RESEND_KEY = process.env.RESEND_API_KEY;
const RECAPTCHA_SECRET = process.env.RECAPTCHA_SECRET;

async function redis(cmd,...args){
  const r = await fetch(`${REDIS_URL}/${cmd}/${args.map(encodeURIComponent).join("/")}`,{
    headers:{Authorization:`Bearer ${REDIS_TOKEN}`}
  });
  return r.json();
}

async function verifyCaptcha(token){
  if(!token) return false;
  const r = await fetch("https://www.google.com/recaptcha/api/siteverify",{
    method:"POST",
    headers:{ "Content-Type":"application/x-www-form-urlencoded" },
    body:new URLSearchParams({
      secret:RECAPTCHA_SECRET,
      response:token
    })
  });
  const j = await r.json();
  return !!j.success;
}

export default async function handler(req,res){
  if(req.method!=="POST") return res.status(405).end();
  const {action} = req.query;
  const body = req.body;

  if(action==="register_sendCode"){
    if(!(await verifyCaptcha(body.captcha)))
      return res.json({ok:false,error:"Подтверди капчу"});

    // логика регистрации (у тебя уже есть)
    return res.json({ok:true});
  }

  if(action==="login"){
    if(!(await verifyCaptcha(body.captcha)))
      return res.json({ok:false,error:"Подтверди капчу"});

    // логика входа
    return res.json({ok:true});
  }

  res.json({ok:false,error:"UNKNOWN_ACTION"});
}
