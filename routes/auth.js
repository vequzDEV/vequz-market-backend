const express = require("express");
const crypto = require("crypto");
const db = require("../database/db");

const router = express.Router();

/* =========================================
   COOKIE HELPERS
========================================= */


function parseCookies(req) {
  const header = req.headers.cookie || "";

  return Object.fromEntries(
    header
      .split(";")
      .map(part => part.trim())
      .filter(Boolean)
      .map(part => {
        const index = part.indexOf("=");

        if (index === -1) {
          return [part, ""];
        }

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

  if (options.httpOnly) {
    cookie += "; HttpOnly";
  }

  if (options.secure) {
    cookie += "; Secure";
  }

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

/* =========================================
   DEBUG
========================================= */

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

/* =========================================
   DISCORD LOGIN
========================================= */

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

/* =========================================
   DISCORD CALLBACK
========================================= */

router.get("/discord/callback", async (req, res) => {
  try {
    const code = req.query.code;
    const state = req.query.state;

    if (!code) {
      return res.status(400).send(`
        <!DOCTYPE html>
        <html lang="de">
        <head>
          <meta charset="UTF-8">
          <meta name="viewport" content="width=device-width,initial-scale=1">
          <title>VEQUZ MARKET</title>
        </head>
        <body>
          <h1>Discord Code fehlt.</h1>
          <p>Diese URL darf nicht direkt geÃ¶ffnet werden.</p>
        </body>
        </html>
      `);
    }

    const cookies = parseCookies(req);
    const savedState = cookies.oauth_state;

    if (!state || !savedState || state !== savedState) {
      return res.status(400).send(`
        <!DOCTYPE html>
        <html lang="de">
        <head>
          <meta charset="UTF-8">
          <meta name="viewport" content="width=device-width,initial-scale=1">
          <title>VEQUZ MARKET</title>
        </head>
        <body>
          <h1>Login abgebrochen.</h1>
          <p>UngÃ¼ltiger OAuth-State.</p>
        </body>
        </html>
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

    /* =====================================
       CODE â ACCESS TOKEN
    ===================================== */

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
      console.error(
        "DISCORD TOKEN ERROR:",
        tokenData
      );

      return res.status(502).send(`
        <h1>Discord Login Fehler</h1>
        <p>Der Discord Authorization Code konnte nicht eingelÃ¶st werden.</p>
      `);
    }

    /* =====================================
       DISCORD USER ABRUFEN
    ===================================== */

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
      console.error(
        "DISCORD USER ERROR:",
        discordUser
      );

      return res.status(502).send(`
        <h1>Discord User Fehler</h1>
        <p>Die Discord-Benutzerdaten konnten nicht geladen werden.</p>
      `);
    }

    /* =====================================
       USER DATEN
    ===================================== */

    const username =
      discordUser.global_name ||
      discordUser.username ||
      "Discord User";

    const email =
      discordUser.email || "";

    let avatar = "";

    if (discordUser.avatar) {
      avatar =
        `https://cdn.discordapp.com/avatars/` +
        `${discordUser.id}/` +
        `${discordUser.avatar}.png`;
    }

    /* =====================================
       USER IN DATABASE SPEICHERN
    ===================================== */

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

    /* =====================================
       ALTE SESSIONS DES USERS LÃSCHEN
    ===================================== */

    db.prepare(`
      DELETE FROM sessions
      WHERE user_id = ?
    `).run(user.id);

    /* =====================================
       NEUE SESSION
    ===================================== */

    const sessionId =
      crypto.randomBytes(32).toString("hex");

    const expiresAt =
      new Date(
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

    /* =====================================
       SESSION COOKIE
    ===================================== */

    setCookie(
      res,
      "vequz_session",
      sessionId,
      {
        maxAge: 7 * 24 * 60 * 60,
        httpOnly: true,
        secure: true,
        sameSite: "Lax"
      }
    );

    clearCookie(
      res,
      "oauth_state"
    );

    /* =====================================
       ERFOLGSSEITE
    ===================================== */

 res.send(`

<!DOCTYPE html>

<html lang="de">

<head>

<meta charset="UTF-8">

<meta name="viewport" content="width=device-width, initial-scale=1.0">

<title>VEQUZ MARKET â Login erfolgreich</title>

<style>

* {

  box-sizing: border-box;

}

html,

body {

  margin: 0;

  width: 100%;

  min-height: 100%;

  font-family: Arial, Helvetica, sans-serif;

  background: #000;

  color: #fff;

}

body {

  min-height: 100vh;

  overflow: hidden;

}

/* FULLSCREEN BACKGROUND */

.welcome {

  position: relative;

  width: 100%;

  min-height: 100vh;

  display: flex;

  align-items: center;

  justify-content: center;

  background-image:

    linear-gradient(

      rgba(0,0,0,0.72),

      rgba(0,0,0,0.82)

    ),

    url("https://cdn.discordapp.com/attachments/1551231906392178798/1551633816173416559/323E32F2-A871-4E3C-AD4A-98C86C960B80.png?ex=6ab2af19&is=6ab15d99&hm=104b4959ed1fe8c1b7524b86a10534f7bf70d967bc98f66b13941f4fc44ad6f9");

  background-size: cover;

  background-position: center;

}

/* YELLOW GLOW */

.welcome::before {

  content: "";

  position: absolute;

  width: 600px;

  height: 600px;

  left: 50%;

  top: 50%;

  transform: translate(-50%, -50%);

  background: #ffff00;

  opacity: 0.08;

  filter: blur(120px);

  border-radius: 50%;

  pointer-events: none;

}

/* CONTENT */

.content {

  position: relative;

  z-index: 2;

  width: min(92%, 900px);

  text-align: center;

  padding: 40px 20px;

}

/* LABEL */

.label {

  display: inline-block;

  margin-bottom: 24px;

  padding: 9px 18px;

  border: 1px solid rgba(255,255,0,0.6);

  border-radius: 999px;

  color: #ffff00;

  font-size: 12px;

  font-weight: 800;

  letter-spacing: 3px;

  text-transform: uppercase;

  background: rgba(0,0,0,0.35);

  box-shadow:

    0 0 20px rgba(255,255,0,0.15);

}

/* CHECK */

.check {

  margin: 0 auto 28px;

  width: 86px;

  height: 86px;

  display: flex;

  align-items: center;

  justify-content: center;

  border-radius: 50%;

  background: #ffff00;

  color: #000;

  font-size: 52px;

  font-weight: 900;

  box-shadow:

    0 0 25px rgba(255,255,0,0.8),

    0 0 80px rgba(255,255,0,0.3);

}

/* TITLE */

h1 {

  margin: 0;

  font-size: clamp(48px, 10vw, 110px);

  line-height: 0.88;

  font-weight: 900;

  letter-spacing: -5px;

  text-transform: uppercase;

  color: #fff;

  text-shadow:

    0 4px 20px rgba(0,0,0,0.8);

}

h1 span {

  display: block;

  color: #ffff00;

  text-shadow:

    0 0 10px rgba(255,255,0,0.9),

    0 0 35px rgba(255,255,0,0.35);

}

/* WELCOME */

.welcome-text {

  margin-top: 30px;

  font-size: 20px;

  color: #bdbdbd;

  line-height: 1.5;

}

.username {

  margin-top: 7px;

  color: #fff;

  font-size: 28px;

  font-weight: 900;

}

/* DIVIDER */

.divider {

  width: 90px;

  height: 2px;

  margin: 30px auto;

  background: #ffff00;

  box-shadow:

    0 0 12px #ffff00;

}

/* BUTTON */

.enter {

  display: inline-flex;

  align-items: center;

  justify-content: center;

  min-width: 270px;

  min-height: 64px;

  padding: 0 35px;

  background: #ffff00;

  color: #000;

  border-radius: 14px;

  text-decoration: none;

  font-size: 17px;

  font-weight: 900;

  letter-spacing: 0.5px;

  transition:

    transform 0.2s ease,

    box-shadow 0.2s ease,

    background 0.2s ease;

}

.enter:hover {

  transform: translateY(-4px);

  background: #ffff66;

  box-shadow:

    0 0 20px rgba(255,255,0,0.9),

    0 0 60px rgba(255,255,0,0.35);

}

/* BRAND */

.brand {

  margin-top: 30px;

  color: rgba(255,255,255,0.45);

  font-size: 11px;

  font-weight: 800;

  letter-spacing: 4px;

  text-transform: uppercase;

}

/* MOBILE */

@media (max-width: 600px) {

  .content {

    width: 94%;

    padding: 25px 12px;

  }

  .label {

    font-size: 10px;

    letter-spacing: 2px;

  }

  .check {

    width: 72px;

    height: 72px;

    font-size: 43px;

    margin-bottom: 24px;

  }

  h1 {

    font-size: 52px;

    letter-spacing: -3px;

  }

  .welcome-text {

    margin-top: 25px;

    font-size: 16px;

  }

  .username {

    font-size: 23px;

  }

  .enter {

    width: 100%;

    min-height: 60px;

    font-size: 16px;

  }

  .brand {

    font-size: 9px;

    letter-spacing: 2px;

  }

}

</style>

</head>

<body>

<section class="welcome">

  <div class="content">

    <div class="label">

      â DISCORD VERIFIED

    </div>

    <div class="check">

      â

    </div>

    <h1>

      LOGIN

      <span>ERFOLGREICH</span>

    </h1>

    <div class="welcome-text">

      Willkommen zurÃ¼ck bei

    </div>

    <div class="username">

      VEQUZ MARKET

    </div>

    <div class="divider"></div>

    <a class="enter" href="/">

      ZURÃCK ZUM MARKET â

    </a>

    <div class="brand">

      VEQUZ MARKET Â· PREMIUM Â· FAST Â· SECURE

    </div>

  </div>

</section>

</body>

</html>

`);/* =========================================
   AKTUELL EINGELOGGTER USER
========================================= */

router.get("/me", (req, res) => {
  try {
    const cookies = parseCookies(req);

    const sessionId =
      cookies.vequz_session;

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
      clearCookie(
        res,
        "vequz_session"
      );

      return res.json({
        ok: true,
        loggedIn: false
      });
    }

    if (
      new Date(session.expires_at).getTime()
      <= Date.now()
    ) {
      db.prepare(`
        DELETE FROM sessions
        WHERE id = ?
      `).run(sessionId);

      clearCookie(
        res,
        "vequz_session"
      );

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
    console.error(
      "SESSION ERROR:",
      error
    );

    return res.status(500).json({
      ok: false,
      error: "Session konnte nicht geprÃ¼ft werden."
    });
  }
});

/* =========================================
   LOGOUT
========================================= */

router.get("/logout", (req, res) => {
  try {
    const cookies = parseCookies(req);

    const sessionId =
      cookies.vequz_session;

    if (sessionId) {
      db.prepare(`
        DELETE FROM sessions
        WHERE id = ?
      `).run(sessionId);
    }

    clearCookie(
      res,
      "vequz_session"
    );

    return res.json({
      ok: true,
      loggedOut: true
    });

  } catch (error) {
    console.error(
      "LOGOUT ERROR:",
      error
    );

    return res.status(500).json({
      ok: false,
      error: "Logout fehlgeschlagen."
    });
  }
});

/* =========================================
   HTML ESCAPE
========================================= */

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

/* =========================================
   EXPORT
========================================= */

module.exports = router;