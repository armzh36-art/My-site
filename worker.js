function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "Content-Type": "application/json" }
  });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // ================= REGISTER =================
    if (url.pathname === "/api/register" && request.method === "POST") {
      const { username, password, email } = await request.json();
      const ip = request.headers.get("CF-Connecting-IP") || "unknown";
      const ua = request.headers.get("User-Agent") || "unknown";

      const existing = await env.DB
        .prepare("SELECT id FROM users WHERE username = ?")
        .bind(username)
        .first();

      if (existing) {
        return json({ error: "Username taken" }, 400);
      }

      const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
      let code = "";
      for (let i = 0; i < 5; i++) {
        code += chars[Math.floor(Math.random() * chars.length)];
      }

      await env.KV_BINDING.put(
        "verify_" + username,
        JSON.stringify({ code, email }),
        { expirationTtl: 300 }
      );

      await env.DB.prepare(
        "INSERT INTO users (username, password, email, email_verified, ip, user_agent) VALUES (?, ?, ?, 0, ?, ?)"
      ).bind(username, password, email, ip, ua).run();

      return json({ success: true, step: "verify_email" });
    }

    // ================= VERIFY =================
    if (url.pathname === "/api/verify" && request.method === "POST") {
      const { username, code } = await request.json();

      const stored = await env.KV_BINDING.get("verify_" + username);
      if (!stored) return json({ error: "Code expired" }, 400);

      const data = JSON.parse(stored);

      if (data.code !== code) {
        return json({ error: "Wrong code" }, 400);
      }

      await env.DB.prepare(
        "UPDATE users SET email_verified = 1 WHERE username = ?"
      ).bind(username).run();

      await env.KV_BINDING.delete("verify_" + username);

      return json({ success: true, step: "verified" });
    }

    // ================= LOGIN =================
    if (url.pathname === "/api/login" && request.method === "POST") {
      const { identifier, password } = await request.json();

      const user = await env.DB
        .prepare("SELECT * FROM users WHERE username = ? OR email = ?")
        .bind(identifier, identifier)
        .first();

      if (!user || user.password !== password) {
        return json({ error: "Wrong credentials" }, 401);
      }

      if (!user.email_verified) {
        return json({ error: "Email not verified" }, 403);
      }

      return json({
        success: true,
        username: user.username
      });
    }

    // ================= FRONTEND =================
    return new Response(`<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Dark Login</title>
<style>
body{background:#0a0a0a;color:#fff;font-family:monospace;display:flex;justify-content:center;align-items:center;height:100vh}
.box{width:320px;background:#111;padding:20px;border:1px solid #333}
input,button{width:100%;padding:10px;margin:5px 0;background:#0a0a0a;color:#fff;border:1px solid #333}
button{cursor:pointer}
.err{color:red;font-size:12px}
</style>
</head>
<body>

<div class="box" id="create">
<h3>REGISTER</h3>
<input id="u" placeholder="username">
<input id="p" placeholder="password">
<input id="e" placeholder="email">
<button onclick="register()">CREATE</button>
<div id="ce" class="err"></div>
</div>

<div class="box" id="verify" style="display:none">
<h3>VERIFY</h3>
<input id="c" placeholder="code">
<button onclick="verify()">VERIFY</button>
<div id="ve" class="err"></div>
</div>

<script>
let tempUser = "";

async function register(){
  const res = await fetch("/api/register", {
    method:"POST",
    headers:{ "Content-Type":"application/json" },
    body: JSON.stringify({
      username: u.value,
      password: p.value,
      email: e.value
    })
  });

  const data = await res.json();

  if(data.step === "verify_email"){
    tempUser = u.value;
    create.style.display = "none";
    verify.style.display = "block";
  } else {
    ce.innerText = data.error || "error";
  }
}

async function verify(){
  const res = await fetch("/api/verify", {
    method:"POST",
    headers:{ "Content-Type":"application/json" },
    body: JSON.stringify({
      username: tempUser,
      code: c.value
    })
  });

  const data = await res.json();

  if(data.step === "verified"){
    document.body.innerHTML = \`
    <div style="background:#0a0a0a;color:#fff;display:flex;justify-content:center;align-items:center;height:100vh;font-family:monospace;text-align:center">
      <div>
        <h2>THANK YOU</h2>
        <p>Thanks for testing this website.</p>
        <p>This project is currently in development.</p>
        <p>A Pastebin-style platform is being built.</p>
      </div>
    </div>\`;
  } else {
    ve.innerText = data.error || "error";
  }
}
</script>

</body>
</html>`, {
      headers: { "Content-Type": "text/html" }
    });
  }
};
