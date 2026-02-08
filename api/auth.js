const REDIS_URL = process.env.UPSTASH_REDIS_REST_URL;
const REDIS_TOKEN = process.env.UPSTASH_REDIS_REST_TOKEN;
const ADMIN_EMAIL = process.env.ADMIN_EMAIL;

/* ================== HELPERS ================== */

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

async function readBody(req) {
  return new Promise((resolve) => {
    let raw = "";
    req.on("data", (c) => (raw += c));
    req.on("end", () => {
      try {
        resolve(raw ? JSON.parse(raw) : {});
      } catch {
        resolve({});
      }
    });
  });
}

function setSession(res, email) {
  res.setHeader(
    "Set-Cookie",
    `session=${encodeURIComponent(email)}; Path=/; HttpOnly; SameSite=Lax`
  );
}

/* ================== HANDLER ================== */

export default async function handler(req, res) {
  try {
    if (req.method !== "POST") {
      return send(res, 405, { ok: false });
    }

    const body = await readBody(req);
    const action = body.action;

    /* ========== REGISTER ========== */
    if (action === "register") {
      const { email, password, username, name } = body;

      if (!email || !password || !username) {
        return send(res, 400, { ok: false, reason: "missing_fields" });
      }

      const exists = await redis("get", `user:${email}`);
      if (exists.result) {
        return send(res, 409, { ok: false, reason: "user_exists" });
      }

      const uname = await redis("get", `username:${username}`);
      if (uname.result) {
        return send(res, 409, { ok: false, reason: "username_taken" });
      }

      const user = {
        email,
        password, // ⚠️ позже захешируешь
        username,
        name: name || "",
        avatar: "",
        badges: email === ADMIN_EMAIL ? ["developer"] : [],
        created: Date.now(),
      };

      await redis("set", `user:${email}`, JSON.stringify(user));
      await redis("set", `username:${username}`, email);

      setSession(res, email);
      return send(res, 200, { ok: true });
    }

    /* ========== LOGIN ========== */
    if (action === "login") {
      const { email, password } = body;

      const r = await redis("get", `user:${email}`);
      if (!r.result) {
        return send(res, 401, { ok: false });
      }

      const user = JSON.parse(r.result);
      if (user.password !== password) {
        return send(res, 401, { ok: false });
      }

      setSession(res, email);
      return send(res, 200, { ok: true });
    }

    /* ========== LOGOUT ========== */
    if (action === "logout") {
      res.setHeader(
        "Set-Cookie",
        "session=; Path=/; Max-Age=0; HttpOnly"
      );
      return send(res, 200, { ok: true });
    }

    return send(res, 400, { ok: false });
  } catch (e) {
    console.error("AUTH ERROR:", e);
    return send(res, 500, { ok: false });
  }
}
