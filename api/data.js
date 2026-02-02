import crypto from "crypto";

/**
 * /api/data?action=...
 * Required ENV:
 * - UPSTASH_REDIS_REST_URL
 * - UPSTASH_REDIS_REST_TOKEN
 *
 * Actions:
 * - post_create  POST { title, body }
 * - posts_get    GET  (?author optional)
 * - post_get     GET  (?id required)
 * - users_search GET  (?q required)  (SCAN)
 * - user_get     GET  (?u required)
 *
 * DM Actions:
 * - dm_init   GET  ?u=username
 * - dm_list   GET
 * - dm_fetch  GET  ?threadId&after
 * - dm_send   POST { threadId, type:"text"|"image", text?, dataUrl? }
 * - dm_edit   POST { threadId, id, text }
 * - dm_delete POST { threadId, id }
 * - dm_pin    POST { threadId, id }
 */

const REDIS_URL = process.env.UPSTASH_REDIS_REST_URL || "";
const REDIS_TOKEN = process.env.UPSTASH_REDIS_REST_TOKEN || "";

function json(res, code, obj) {
  res.statusCode = code;
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("X-Frame-Options", "DENY");
  res.end(JSON.stringify(obj));
}

async function redis(cmd, ...args) {
  const url = `${REDIS_URL}/${cmd}/${args.map(encodeURIComponent).join("/")}`;
  const r = await fetch(url, { headers: { Authorization: `Bearer ${REDIS_TOKEN}` } });
  const j = await r.json().catch(() => ({}));
  if (j.error) throw new Error(`Redis: ${j.error}`);
  return j;
}

async function readBody(req) {
  if (req.body && typeof req.body === "object") return req.body;
  const chunks = [];
  for await (const c of req) chunks.push(Buffer.isBuffer(c) ? c : Buffer.from(c));
  const raw = Buffer.concat(chunks).toString("utf8").trim();
  if (!raw) return {};
  try { return JSON.parse(raw); } catch { return {}; }
}

function getSid(req) {
  const c = String(req.headers.cookie || "");
  return (c.match(/(?:^|;\s*)sid=([^;]+)/) || [])[1] || "";
}

async function isBanned(email) {
  const b = await redis("get", `ban:email:${email}`);
  return !!b.result;
}

async function requireAuth(req, res) {
  const sid = getSid(req);
  if (!sid) { json(res, 401, { ok:false, error:"NO_SESSION" }); return null; }
  const se = await redis("get", `sess:${sid}`);
  if (!se.result) { json(res, 401, { ok:false, error:"NO_SESSION" }); return null; }
  const email = se.result;

  if (await isBanned(email)) {
    json(res, 403, { ok:false, error:"BANNED" });
    return null;
  }
  return email;
}

function normUser(u) {
  u = String(u || "").trim().toLowerCase();
  if (u.startsWith("@")) u = u.slice(1);
  return u;
}

function snippetFrom(text) {
  const t = String(text || "").replace(/\s+/g, " ").trim();
  return t.slice(0, 180);
}

function threadIdFor(a, b) {
  const x = [a, b].sort().join("|");
  return crypto.createHash("sha256").update(x).digest("hex").slice(0, 32);
}

async function threadMeta(threadId) {
  const raw = (await redis("get", `dm:thread:${threadId}:meta`)).result;
  return raw ? JSON.parse(raw) : null;
}

function isParticipant(meta, email) {
  return meta && (meta.a === email || meta.b === email);
}

export default async function handler(req, res) {
  try {
    if (!REDIS_URL || !REDIS_TOKEN) return json(res, 500, { ok:false, error:"SERVER_MISCONFIGURED" });

    const action = String(req.query.action || "");
    const body = await readBody(req);

    const email = await requireAuth(req, res);
    if (!email) return;

    // -------- POSTS --------
    if (action === "post_create") {
      if (req.method !== "POST") return json(res, 405, { ok:false, error:"METHOD" });

      const title = String(body.title || "").trim();
      const text = String(body.body || "").trim();

      if (title.length < 3) return json(res, 200, { ok:false, error:"BAD_TITLE" });
      if (text.length < 10) return json(res, 200, { ok:false, error:"BAD_BODY" });
      if (text.length > 20000) return json(res, 200, { ok:false, error:"TOO_LARGE" });

      const meRaw = (await redis("get", `user:email:${email}`)).result;
      if (!meRaw) return json(res, 200, { ok:false, error:"NO_PROFILE" });
      const me = JSON.parse(meRaw);

      const id = crypto.randomBytes(8).toString("hex");
      const post = {
        id,
        title: title.slice(0, 140),
        body: text,
        snippet: snippetFrom(text),
        username: me.username,
        avatar: me.avatar || "",
        badges: me.badges || [],
        createdAt: Date.now()
      };

      await redis("set", `post:${id}`, JSON.stringify(post));
      await redis("lpush", "posts", id);
      await redis("ltrim", "posts", "0", "300");

      return json(res, 200, { ok:true, id });
    }

    if (action === "posts_get") {
      const author = normUser(req.query.author || "");
      const ids = (await redis("lrange", "posts", "0", "40")).result || [];
      const out = [];

      for (const id of ids) {
        const p = await redis("get", `post:${id}`);
        if (!p.result) continue;
        const post = JSON.parse(p.result);
        if (author && String(post.username || "").toLowerCase() !== author) continue;
        out.push(post);
      }
      return json(res, 200, { ok:true, posts: out });
    }

    if (action === "post_get") {
      const id = String(req.query.id || "");
      if (!id) return json(res, 200, { ok:false, error:"BAD_ID" });
      const p = await redis("get", `post:${id}`);
      if (!p.result) return json(res, 200, { ok:false, error:"NOT_FOUND" });
      return json(res, 200, { ok:true, post: JSON.parse(p.result) });
    }

    // -------- USERS --------
    if (action === "users_search") {
      const q = normUser(req.query.q || "");
      if (q.length < 2) return json(res, 200, { ok:true, users: [] });

      const users = [];
      let cursor = "0";

      for (let i = 0; i < 10 && users.length < 20; i++) {
        const s = await redis("scan", cursor, "match", "user:username:*", "count", "250");
        cursor = String(s.result?.[0] ?? "0");
        const keys = s.result?.[1] || [];

        for (const k of keys) {
          const uname = String(k).slice("user:username:".length);
          if (!uname.includes(q)) continue;

          const em = (await redis("get", k)).result;
          if (!em) continue;

          const raw = (await redis("get", `user:email:${em}`)).result;
          if (!raw) continue;

          const u = JSON.parse(raw);
          users.push({
            username: u.username,
            name: u.name || "",
            avatar: u.avatar || "",
            badges: u.badges || []
          });

          if (users.length >= 20) break;
        }

        if (cursor === "0") break;
      }

      return json(res, 200, { ok:true, users });
    }

    if (action === "user_get") {
      const u = normUser(req.query.u || "");
      if (!u) return json(res, 200, { ok:false, error:"BAD_USER" });

      const em = (await redis("get", `user:username:${u}`)).result;
      if (!em) return json(res, 200, { ok:false, error:"NOT_FOUND" });

      const raw = (await redis("get", `user:email:${em}`)).result;
      if (!raw) return json(res, 200, { ok:false, error:"NOT_FOUND" });

      const user = JSON.parse(raw);
      return json(res, 200, { ok:true, user:{
        username: user.username,
        name: user.name || "",
        about: user.about || "",
        avatar: user.avatar || "",
        badges: user.badges || []
      }});
    }

    // -------- DM / CHATS --------

    if (action === "dm_init") {
      const peerU = normUser(req.query.u || "");
      const peerEmail = (await redis("get", `user:username:${peerU}`)).result;
      if (!peerEmail) return json(res, 200, { ok:false, error:"NO_USER" });

      const tid = threadIdFor(email, peerEmail);

      const metaKey = `dm:thread:${tid}:meta`;
      const metaExisting = (await redis("get", metaKey)).result;
      if (!metaExisting) {
        await redis("set", metaKey, JSON.stringify({
          tid, a: email, b: peerEmail, pinned: 0, lastTs: Date.now()
        }));
      }

      // recents for both users
      await redis("lrem", `dm:user:${email}:threads`, "0", tid);
      await redis("lpush", `dm:user:${email}:threads`, tid);
      await redis("ltrim", `dm:user:${email}:threads`, "0", "50");

      await redis("lrem", `dm:user:${peerEmail}:threads`, "0", tid);
      await redis("lpush", `dm:user:${peerEmail}:threads`, tid);
      await redis("ltrim", `dm:user:${peerEmail}:threads`, "0", "50");

      return json(res, 200, { ok:true, threadId: tid });
    }

    if (action === "dm_list") {
      const tids = (await redis("lrange", `dm:user:${email}:threads`, "0", "30")).result || [];
      const out = [];

      for (const tid of tids) {
        const meta = await threadMeta(tid);
        if (!meta || !isParticipant(meta, email)) continue;

        const peerEmail = (meta.a === email) ? meta.b : meta.a;
        const peerRaw = (await redis("get", `user:email:${peerEmail}`)).result;
        if (!peerRaw) continue;
        const peer = JSON.parse(peerRaw);

        const lastId = Number((await redis("get", `dm:thread:${tid}:lastId`)).result || 0);
        let preview = "";
        if (lastId) {
          const m = (await redis("get", `dm:thread:${tid}:m:${lastId}`)).result;
          if (m) {
            const msg = JSON.parse(m);
            if (msg.deleted) preview = "[deleted]";
            else preview = (msg.type === "image") ? "[photo]" : String(msg.text || "").slice(0, 60);
          }
        }

        out.push({
          threadId: tid,
          peer: { username: peer.username, name: peer.name || "", avatar: peer.avatar || "", badges: peer.badges || [] },
          pinnedId: meta.pinned || 0,
          lastTs: meta.lastTs || 0,
          preview
        });
      }

      return json(res, 200, { ok:true, chats: out });
    }

    if (action === "dm_fetch") {
      const tid = String(req.query.threadId || "");
      const after = Number(req.query.after || 0);

      const meta = await threadMeta(tid);
      if (!meta) return json(res, 200, { ok:false, error:"NO_THREAD" });
      if (!isParticipant(meta, email)) return json(res, 403, { ok:false, error:"FORBIDDEN" });

      const ids = (await redis("lrange", `dm:thread:${tid}:ids`, "0", "120")).result || [];
      const want = ids.map(Number).filter(n => n > after).sort((a,b)=>a-b);

      const out = [];
      for (const id of want) {
        const raw = (await redis("get", `dm:thread:${tid}:m:${id}`)).result;
        if (raw) out.push(JSON.parse(raw));
      }

      return json(res, 200, { ok:true, messages: out, pinned: meta.pinned || 0 });
    }

    if (action === "dm_send") {
      if (req.method !== "POST") return json(res, 405, { ok:false, error:"METHOD" });

      const tid = String(body.threadId || "");
      const type = String(body.type || "text");
      const text = String(body.text || "").trim();
      const dataUrl = String(body.dataUrl || "");

      const meta = await threadMeta(tid);
      if (!meta) return json(res, 200, { ok:false, error:"NO_THREAD" });
      if (!isParticipant(meta, email)) return json(res, 403, { ok:false, error:"FORBIDDEN" });

      if (type === "text") {
        if (!text) return json(res, 200, { ok:false, error:"EMPTY" });
        if (text.length > 4000) return json(res, 200, { ok:false, error:"TOO_LARGE" });
      } else if (type === "image") {
        if (!dataUrl.startsWith("data:image/")) return json(res, 200, { ok:false, error:"BAD_IMAGE" });
        if (dataUrl.length > 1_800_000) return json(res, 200, { ok:false, error:"TOO_LARGE" });
      } else {
        return json(res, 200, { ok:false, error:"BAD_TYPE" });
      }

      const seq = await redis("incr", `dm:thread:${tid}:seq`);
      const id = Number(seq.result || 0);

      const msg = {
        id,
        threadId: tid,
        from: email,
        ts: Date.now(),
        type,
        text: type === "text" ? text : "",
        dataUrl: type === "image" ? dataUrl : "",
        editedAt: 0,
        deleted: false
      };

      await redis("set", `dm:thread:${tid}:m:${id}`, JSON.stringify(msg));
      await redis("lpush", `dm:thread:${tid}:ids`, String(id));
      await redis("ltrim", `dm:thread:${tid}:ids`, "0", "600");
      await redis("set", `dm:thread:${tid}:lastId`, String(id));

      meta.lastTs = Date.now();
      await redis("set", `dm:thread:${tid}:meta`, JSON.stringify(meta));

      // bump recents
      await redis("lrem", `dm:user:${meta.a}:threads`, "0", tid);
      await redis("lpush", `dm:user:${meta.a}:threads`, tid);
      await redis("ltrim", `dm:user:${meta.a}:threads`, "0", "50");
      await redis("lrem", `dm:user:${meta.b}:threads`, "0", tid);
      await redis("lpush", `dm:user:${meta.b}:threads`, tid);
      await redis("ltrim", `dm:user:${meta.b}:threads`, "0", "50");

      return json(res, 200, { ok:true, id });
    }

    if (action === "dm_edit") {
      if (req.method !== "POST") return json(res, 405, { ok:false, error:"METHOD" });

      const tid = String(body.threadId || "");
      const id = Number(body.id || 0);
      const text = String(body.text || "").trim();

      if (!tid || !id) return json(res, 200, { ok:false, error:"BAD" });
      if (!text || text.length > 4000) return json(res, 200, { ok:false, error:"BAD_TEXT" });

      const meta = await threadMeta(tid);
      if (!meta) return json(res, 200, { ok:false, error:"NO_THREAD" });
      if (!isParticipant(meta, email)) return json(res, 403, { ok:false, error:"FORBIDDEN" });

      const raw = (await redis("get", `dm:thread:${tid}:m:${id}`)).result;
      if (!raw) return json(res, 200, { ok:false, error:"NOT_FOUND" });

      const msg = JSON.parse(raw);
      if (msg.from !== email) return json(res, 403, { ok:false, error:"FORBIDDEN" });
      if (msg.deleted) return json(res, 200, { ok:false, error:"DELETED" });
      if (msg.type !== "text") return json(res, 200, { ok:false, error:"BAD_TYPE" });

      msg.text = text;
      msg.editedAt = Date.now();
      await redis("set", `dm:thread:${tid}:m:${id}`, JSON.stringify(msg));

      return json(res, 200, { ok:true });
    }

    if (action === "dm_delete") {
      if (req.method !== "POST") return json(res, 405, { ok:false, error:"METHOD" });

      const tid = String(body.threadId || "");
      const id = Number(body.id || 0);

      const meta = await threadMeta(tid);
      if (!meta) return json(res, 200, { ok:false, error:"NO_THREAD" });
      if (!isParticipant(meta, email)) return json(res, 403, { ok:false, error:"FORBIDDEN" });

      const raw = (await redis("get", `dm:thread:${tid}:m:${id}`)).result;
      if (!raw) return json(res, 200, { ok:false, error:"NOT_FOUND" });

      const msg = JSON.parse(raw);
      if (msg.from !== email) return json(res, 403, { ok:false, error:"FORBIDDEN" });

      msg.deleted = true;
      msg.text = "";
      msg.dataUrl = "";
      msg.editedAt = Date.now();
      await redis("set", `dm:thread:${tid}:m:${id}`, JSON.stringify(msg));

      return json(res, 200, { ok:true });
    }

    if (action === "dm_pin") {
      if (req.method !== "POST") return json(res, 405, { ok:false, error:"METHOD" });

      const tid = String(body.threadId || "");
      const id = Number(body.id || 0);

      const meta = await threadMeta(tid);
      if (!meta) return json(res, 200, { ok:false, error:"NO_THREAD" });
      if (!isParticipant(meta, email)) return json(res, 403, { ok:false, error:"FORBIDDEN" });

      meta.pinned = id;
      await redis("set", `dm:thread:${tid}:meta`, JSON.stringify(meta));

      return json(res, 200, { ok:true });
    }

    return json(res, 404, { ok:false, error:"UNKNOWN_ACTION" });
  } catch (e) {
    return json(res, 500, { ok:false, error:"SERVER_ERROR", detail: String(e?.message || e) });
  }
}
