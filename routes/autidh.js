const express = require("express");
const crypto = require("crypto");
const db = require("../database/db");

const router = express.Router();

function parseCookies(req) {
  const header = req.headers.cookie || "";

  return Object.fromEntries(
    header
      .split(";")
      .map(part => part.trim())
      .filter(Boolean)
      .map(part => {
        const index = part.indexOf("=");

        if (index === -1) return [part, ""];

        return [
          decodeURIComponent(part.slice(0, index)),
          decodeURIComponent(part.slice(index + 1))
        ];
      })
  );
}

function setCookie(res, name, value, options = {}) {
  let cookie = `${name}=${encodeURIComponent(value)}; Path=/`;

  if (options.maxAge !== undefined) {
    cookie += `; Max-Age=${options.maxAge}`;
  }

  if (options.httpOnly) cookie += "; HttpOnly";
  if (options.secure) cookie += "; Secure";

  if (options.sameSite) {
    cookie += `; SameSite=${options.sameSite}`;
  }

  res.append("Set-Cookie", cookie);
}

function clearCookie(res, name) {
  res.append(
    "Set-Cookie",
    `${name}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax`
  );
}

/* =========================
   DEBUG
========================= */

router.get("/debug", (req, res) => {
  const clientId = process.env.DISCORD_CLIENT_ID || "";
  const clientSecret = process.env.DISCORD_CLIENT_SECRET || "";
  const redirectUri = process.env.DISCORD_REDIRECT_URI || "";

  res.json({
    ok: true,
    discord: {
      client_id_loaded: Boolean(clientId),
      client_secret_loaded: Boolean(clientSecret),
      redirect_uri_loaded: Boolean(redirectUri),
      client_id_length: clientId.length,
      client_secret_length: clientSecret.length,
      redirect_uri: redirectUri || null
    }
  });
});

/* =========================
   DISCORD LOGIN
========================= */

router.get("/discord", (req, res) => {
  const clientId = process.env.DISCORD_CLIENT_ID;
  const clientSecret = process.env.DISCORD_CLIENT_SECRET;
  const redirectUri = process.env.DISCORD_REDIRECT_URI;

  if (!clientId || !clientSecret || !redirectUri) {
    return res.status(503).json({
      ok: false,
      error: "Discord Login noch nicht eingerichtet.",
      debug: {
        client_id_loaded: Boolean(clientId),
        client_secret_loaded: Boolean(clientSecret),
        redirect_uri_loaded: Boolean(redirectUri)
      }
    });
  }

  const state = crypto.randomBytes(32).toString("hex");

  setCookie(res, "oauth_state", state, {
    maxAge: 600,
    httpOnly: true,
    secure: true,
    sameSite: "Lax"
  });

  const params = new URLSearchParams({
    client_id: clientId,
    redirect_uri: redirectUri,
    response_type: "code",
    scope: "identify email",
    state
  });

  res.redirect(
    "https://discord.com/oauth2/authorize?" +
    params.toString()
  );
});

/* =========================
   DISCORD CALLBACK
========================= */

router.get("/discord/callback", async (req, res) => {
  try {
    const { code, state } = req.query;

    if (!code) {
      return res.status(400).send(`
        <h1>Discord Code fehlt.</h1>
        <p>Diese Callback-URL darf nicht direkt geöffnet werden.</p>
      `);
    }

    const cookies = parseCookies(req);
    const savedState = cookies.oauth_state;

    if (!state || !savedState || state !== savedState) {
      return res.status(400).send(`
        <h1>Login abgebrochen.</h1>
        <p>Ungültiger OAuth-State.</p>
      `);
    }

    const clientId = process.env.DISCORD_CLIENT_ID;
    const clientSecret = process.env.DISCORD_CLIENT_SECRET;
    const redirectUri = process.env.DISCORD_REDIRECT_URI;

    if (!clientId || !clientSecret || !redirectUri) {
      return res.status(503).send(`
        <h1>Discord Login nicht eingerichtet</h1>
        <p>Discord Environment Variables fehlen.</p>
      `);
    }

    const tokenResponse = await fetch(
      "https://discord.com/api/oauth2/token",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded"
        },
        body: new URLSearchParams({
          client_id: clientId,
          client_secret: clientSecret,
          grant_type: "authorization_code",
          code: String(code),
          redirect_uri: redirectUri
        })
      }
    );

    const tokenData = await tokenResponse.json();

    if (!tokenResponse.ok || !tokenData.access_token) {
      console.error("DISCORD TOKEN ERROR:", tokenData);

      return res.status(502).send(`
        <h1>Discord Login Fehler</h1>
        <p>Der Discord Authorization Code konnte nicht eingelöst werden.</p>
      `);
    }

    const userResponse = await fetch(
      "https://discord.com/api/users/@me",
      {
        headers: {
          Authorization: `Bearer ${tokenData.access_token}`
        }
      }
    );

    const discordUser = await userResponse.json();

    if (!userResponse.ok || !discordUser.id) {
      console.error("DISCORD USER ERROR:", discordUser);

      return res.status(502).send(`
        <h1>Discord User Fehler</h1>
        <p>Die Discord-Benutzerdaten konnten nicht geladen werden.</p>
      `);
    }

    const username =
      discordUser.global_name ||
      discordUser.username ||
      "Discord User";

    const email = discordUser.email || "";

    const avatar = discordUser.avatar
      ? `https://cdn.discordapp.com/avatars/${discordUser.id}/${discordUser.avatar}.png`
      : "";

    db.prepare(`
      INSERT INTO users
        (discord_id, username, email, avatar)
      VALUES
        (?, ?, ?, ?)

      ON CONFLICT(discord_id)
      DO UPDATE SET
        username = excluded.username,
        email = excluded.email,
        avatar = excluded.avatar
    `).run(
      discordUser.id,
      username,
      email,
      avatar
    );

    const user = db.prepare(`
      SELECT *
      FROM users
      WHERE discord_id = ?
    `).get(discordUser.id);

    if (!user) {
      return res.status(500).send(`
        <h1>Database Fehler</h1>
        <p>Der Benutzer konnte nicht gespeichert werden.</p>
      `);
    }

    db.prepare(`
      DELETE FROM sessions
      WHERE user_id = ?
    `).run(user.id);

    const sessionId = crypto.randomBytes(32).toString("hex");

    const expiresAt = new Date(
      Date.now() + 7 * 24 * 60 * 60 * 1000
    ).toISOString();

    db.prepare(`
      INSERT INTO sessions
        (id, user_id, expires_at)
      VALUES
        (?, ?, ?)
    `).run(
      sessionId,
      user.id,
      expiresAt
    );

    setCookie(res, "vequz_session", sessionId, {
      maxAge: 7 * 24 * 60 * 60,
      httpOnly: true,
      secure: true,
      sameSite: "Lax"
    });

    clearCookie(res, "oauth_state");

    res.send(`
<!DOCTYPE html>
<html lang="de">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>VEQUZ MARKET — Login</title>

<style>
* {
  box-sizing: border-box;
}

body {
  margin: 0;
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 20px;
  background:
    radial-gradient(circle at top, #202000, #070707 45%, #000);
  color: white;
  font-family: Arial, sans-serif;
}

.card {
  width: min(100%, 460px);
  padding: 42px 28px;
  text-align: center;
  background: rgba(15,15,15,.96);
  border: 1px solid #333;
  border-radius: 20px;
  box-shadow: 0 0 40px rgba(255,255,0,.12);
}

.check {
  width: 70px;
  height: 70px;
  margin: 0 auto 22px;
  display: flex;
  align-items: center;
  justify-content: center;
  border-radius: 50%;
  background: #ffff00;
  color: #000;
  font-size: 38px;
  font-weight: bold;
}

h1 {
  margin: 0 0 12px;
  font-size: 27px;
}

p {
  margin: 8px 0;
  color: #aaa;
}

.name {
  color: #ffff00;
  font-weight: bold;
  margin-top: 14px;
}

button {
  margin-top: 25px;
  padding: 13px 24px;
  border: 0;
  border-radius: 10px;
  background: #ffff00;
  color: #000;
  font-weight: bold;
  cursor: pointer;
}
</style>
</head>

<body>

<div class="card">

  <div class="check">✓</div>

  <h1>LOGIN ERFOLGREICH</h1>

  <p>
    Willkommen bei <strong>VEQUZ MARKET</strong>
  </p>

  <p class="name">
    ${escapeHtml(username)}
  </p>

  <button onclick="history.back()">
    ZURÜCK
  </button>

</div>

</body>
</html>
    `);

  } catch (error) {
    console.error("DISCORD OAUTH ERROR:", error);

    res.status(500).send(`
      <h1>VEQUZ MARKET</h1>
      <p>Beim Discord Login ist ein Serverfehler aufgetreten.</p>
    `);
  }
});

/* =========================
   CURRENT USER
========================= */

router.get("/me", (req, res) => {
  try {
    const cookies = parseCookies(req);
    const sessionId = cookies.vequz_session;

    if (!sessionId) {
      return res.json({
        ok: true,
        loggedIn: false
      });
    }

    const session = db.prepare(`
      SELECT
        sessions.id,
        sessions.expires_at,
        users.id AS user_id,
        users.discord_id,
        users.username,
        users.email,
        users.avatar,
        users.created_at
      FROM sessions
      JOIN users
        ON users.id = sessions.user_id
      WHERE sessions.id = ?
    `).get(sessionId);

    if (!session) {
      clearCookie(res, "vequz_session");

      return res.json({
        ok: true,
        loggedIn: false
      });
    }

    if (
      new Date(session.expires_at).getTime() <= Date.now()
    ) {
      db.prepare(`
        DELETE FROM sessions
        WHERE id = ?
      `).run(sessionId);

      clearCookie(res, "vequz_session");

      return res.json({
        ok: true,
        loggedIn: false
      });
    }

    return res.json({
      ok: true,
      loggedIn: true,
      user: {
        id: session.user_id,
        discord_id: session.discord_id,
        username: session.username,
        email: session.email,
        avatar: session.avatar,
        created_at: session.created_at
      }
    });

  } catch (error) {
    console.error("SESSION ERROR:", error);

    return res.status(500).json({
      ok: false,
      error: "Session konnte nicht geprüft werden."
    });
  }
});

/* =========================
   LOGOUT
========================= */

router.get("/logout", (req, res) => {
  try {
    const cookies = parseCookies(req);
    const sessionId = cookies.vequz_session;

    if (sessionId) {
      db.prepare(`
        DELETE FROM sessions
        WHERE id = ?
      `).run(sessionId);
    }

    clearCookie(res, "vequz_session");

    res.json({
      ok: true,
      loggedOut: true
    });

  } catch (error) {
    console.error("LOGOUT ERROR:", error);

    res.status(500).json({
      ok: false,
      error: "Logout fehlgeschlagen."
    });
  }
});

/* =========================
   HTML ESCAPE
========================= */

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

/* =========================
   EXPORT
========================= */

module.exports = router;