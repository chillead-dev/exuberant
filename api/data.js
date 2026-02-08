const REDIS_URL = process.env.UPSTASH_REDIS_REST_URL;
const REDIS_TOKEN = process.env.UPSTASH_REDIS_REST_TOKEN;

async function redis(command, ...args) {
  const r = await fetch(REDIS_URL, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${REDIS_TOKEN}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ command, args }),
  });
  return r.json();
}

function send(res, status, data) {
  res.statusCode = status;
  res.setHeader("Content-Type", "application/json");
  res.end(JSON.stringify(data));
}

function getSession(req) {
  const cookies = {};
  (req.headers.cookie || "").split(";").forEach((p) => {
    const [k, v] = p.trim().split("=");
    if (k) cookies[k] = decodeURIComponent(v || "");
  });
  return cookies.session;
}

function threadId(a, b) {
  return [a, b].sort().join("::");
}

export default async function handler(req, res) {
  try {
    const email = getSession(req);
    if (!email) return send(res, 401, { ok: false });

    const rawUser = await redis("get", `user:${email}`);
    if (!rawUser.result) return send(res, 401, { ok: false });

    /* ===== CHAT INIT ===== */
    if (req.query.action === "init") {
      const peerUsername = req.query.u;
      const peerEmail = (await redis("get", `username:${peerUsername}`)).result;
      if (!peerEmail) return send(res, 404, { ok: false });

      const tid = threadId(email, peerEmail);

      await redis("sadd", `chats:${email}`, tid);
      await redis("sadd", `chats:${peerEmail}`, tid);

      return send(res, 200, { ok: true, threadId: tid });
    }

    /* ===== CHAT LIST ===== */
    if (req.query.action === "list") {
      const r = await redis("smembers", `chats:${email}`);
      const chats = [];

      for (const tid of r.result || []) {
        const [a, b] = tid.split("::");
        const peer = a === email ? b : a;
        const u = JSON.parse((await redis("get", `user:${peer}`)).result);
        chats.push({ threadId: tid, peer: u });
      }

      return send(res, 200, { ok: true, chats });
    }

    /* ===== SEND MESSAGE ===== */
    if (req.query.action === "send" && req.method === "POST") {
      let raw = "";
      for await (const c of req) raw += c;
      const body = raw ? JSON.parse(raw) : {};

      const msg = {
        id: Date.now(),
        from: email,
        text: body.text || "",
        ts: Date.now(),
      };

      await redis("rpush", `msgs:${body.threadId}`, JSON.stringify(msg));
      return send(res, 200, { ok: true });
    }

    /* ===== FETCH ===== */
    if (req.query.action === "fetch") {
      const r = await redis("lrange", `msgs:${req.query.threadId}`, 0, -1);
      return send(res, 200, {
        ok: true,
        messages: (r.result || []).map(JSON.parse),
      });
    }

    return send(res, 400, { ok: false });
  } catch (e) {
    console.error("DATA ERROR:", e);
    return send(res, 500, { ok: false });
  }
}
