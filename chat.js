const params = new URLSearchParams(location.search);
let threadId = params.get("tid");
const username = params.get("u");
let lastId = 0;

async function api(action, opts={}) {
  const r = await fetch(`/api/data?action=${action}`, {
    method: opts.method || "GET",
    credentials: "include",
    headers: { "Content-Type": "application/json" },
    body: opts.body ? JSON.stringify(opts.body) : null
  });
  return r.json();
}

async function init() {
  if (!threadId && username) {
    const r = await api("dm_init&u="+encodeURIComponent(username));
    threadId = r.threadId;
    history.replaceState(null,"",`?tid=${threadId}`);
  }
  load();
  setInterval(load, 1500);
}

async function load() {
  const r = await api(`dm_fetch&threadId=${threadId}&after=${lastId}`);
  if (!r.ok) return;

  for (const m of r.messages) {
    render(m);
    lastId = Math.max(lastId, m.id);
  }
}

function render(m) {
  const el = document.createElement("div");
  el.className = "msg " + (m.from === "me" ? "me" : "them");

  if (m.deleted) {
    el.innerHTML = `<i class="muted">сообщение удалено</i>`;
  } else if (m.type === "image") {
    el.innerHTML = `<img src="${m.dataUrl}" class="img">`;
  } else {
    el.textContent = m.text;
  }

  document.getElementById("messages").appendChild(el);
  el.scrollIntoView({ behavior:"smooth", block:"end" });
}

async function send() {
  const text = document.getElementById("text");
  if (!text.value.trim()) return;

  await api("dm_send", {
    method:"POST",
    body:{ threadId, type:"text", text:text.value }
  });

  text.value = "";
}

document.getElementById("file").onchange = async e => {
  const f = e.target.files[0];
  if (!f) return;
  const r = new FileReader();
  r.onload = async () => {
    await api("dm_send", {
      method:"POST",
      body:{ threadId, type:"image", dataUrl:r.result }
    });
  };
  r.readAsDataURL(f);
};

init();
