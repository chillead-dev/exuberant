import busboy from "busboy";
import { getUserByEmail, saveUser, requireAuth } from "./_lib.js";

export default async function handler(req,res){
  if (req.method !== "POST") return res.status(405).end();
  const email = await requireAuth(req,res);

  const bb = busboy({ headers:req.headers });
  let buf, mime;

  bb.on("file",(_,file,info)=>{
    mime = info.mimeType;
    const arr=[];
    file.on("data",d=>arr.push(d));
    file.on("end",()=>buf=Buffer.concat(arr));
  });

  bb.on("finish", async ()=>{
    if (!buf) return res.json({ ok:false });
    const user = await getUserByEmail(email);
    user.avatar = `data:${mime};base64,${buf.toString("base64")}`;
    await saveUser(user);
    res.json({ ok:true });
  });

  req.pipe(bb);
}
