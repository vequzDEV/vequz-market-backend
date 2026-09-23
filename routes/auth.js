const express = require("express");
const crypto = require("crypto");
const db = require("../database/db");

const router = express.Router();

const CLIENT_ID = process.env.DISCORD_CLIENT_ID;
const CLIENT_SECRET = process.env.DISCORD_CLIENT_SECRET;
const REDIRECT_URI = process.env.DISCORD_REDIRECT_URI;

function parseCookies(req) {
  const header = req.headers.cookie || "";
  const cookies = {};

  header.split(";").forEach(part => {
    const index = part.indexOf("=");

    if (index === -1) return;

    const name = part.slice(0, index).trim();
    const value = part.slice(index + 1).trim();

    cookies[name] = decodeURIComponent(value);
  });

  return cookies;
}

function setCookie(res, name, value, options = {}) {
  let cookie = `${name}=${encodeURIComponent(value)}; Path=/`;

  if (options.httpOnly) {
    cookie += "; HttpOnly";
  }

  if (options.secure) {
    cookie += "; Secure";
  }

  if (options.sameSite) {
    cookie += `; SameSite=${options.sameSite}`;
  }

  if (options.maxAge !== undefined) {
    cookie += `; Max-Age=${options.maxAge}`;
  }

  res.append("Set-Cookie", cookie);
}

function clearCookie(res, name) {
  res.append(
    "Set-Cookie",
    `${name}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax`
  );
}

function escapeHtml(value) {
  return String(value || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}


/* DEBUG */

router.get("/debug", (req, res) => {
  res.json({
    ok: true,
    discordClientId: !!CLIENT_ID,
    discordClientSecret: !!CLIENT_SECRET,
    discordRedirectUri: !!REDIRECT_URI,
    redirectUri: REDIRECT_URI || null,
    nodeEnv: process.env.NODE_ENV || "production"
  });
});


/* DISCORD LOGIN */

router.get("/discord", (req, res) => {
  if (!CLIENT_ID || !CLIENT_SECRET || !REDIRECT_URI) {
    return res.status(503).json({
      ok: false,
      error: "Discord OAuth ist nicht vollstÃ¤ndig eingerichtet."
    });
  }

  const state = crypto.randomBytes(32).toString("hex");

  setCookie(res, "oauth_state", state, {
    httpOnly: true,
    secure: true,
    sameSite: "Lax",
    maxAge: 600
  });

  const params = new URLSearchParams({
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    response_type: "code",
    scope: "identify email",
    state
  });

  res.redirect(
    "https://discord.com/oauth2/authorize?" + params.toString()
  );
});


/* DISCORD CALLBACK */

router.get("/discord/callback", async (req, res) => {
  try {
    const { code, state } = req.query;
    const cookies = parseCookies(req);

    if (!code) {
      return res.status(400).send("Discord Code fehlt.");
    }

    if (
      !state ||
      !cookies.oauth_state ||
      state !== cookies.oauth_state
    ) {
      return res.status(400).send(`
<!DOCTYPE html>
<html lang="de">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>VEQUZ MARKET â OAuth Fehler</title>

<style>

body {
  margin: 0;
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  background: #000;
  color: #fff;
  font-family: Arial, sans-serif;
  text-align: center;
}

.box {
  width: min(90%, 500px);
  padding: 40px;
  border: 1px solid #ffff00;
  border-radius: 18px;
  background: #0b0b0b;
  box-shadow: 0 0 40px rgba(255,255,0,.15);
}

h1 {
  color: #ffff00;
}

p {
  color: #aaa;
}

</style>
</head>

<body>

<div class="box">

<h1>OAUTH FEHLER</h1>

<p>UngÃ¼ltiger OAuth State.</p>

<p>Bitte starte den Discord-Login erneut.</p>

</div>

</body>
</html>
      `);
    }

    clearCookie(res, "oauth_state");


    /* TOKEN */

    const tokenResponse = await fetch(
      "https://discord.com/api/oauth2/token",
      {
        method: "POST",

        headers: {
          "Content-Type": "application/x-www-form-urlencoded"
        },

        body: new URLSearchParams({
          client_id: CLIENT_ID,
          client_secret: CLIENT_SECRET,
          grant_type: "authorization_code",
          code,
          redirect_uri: REDIRECT_URI
        })
      }
    );

    const tokenData = await tokenResponse.json();

    if (!tokenResponse.ok) {
      console.error(
        "Discord Token Error:",
        tokenData
      );

      return res.status(400).send(
        "Discord Token konnte nicht abgerufen werden."
      );
    }


    /* DISCORD USER */

    const userResponse = await fetch(
      "https://discord.com/api/users/@me",
      {
        headers: {
          Authorization:
            `Bearer ${tokenData.access_token}`
        }
      }
    );

    const user = await userResponse.json();

    if (!userResponse.ok) {
      console.error(
        "Discord User Error:",
        user
      );

      return res.status(400).send(
        "Discord Benutzer konnte nicht geladen werden."
      );
    }


    /* USER SPEICHERN */

    const existingUser = db
      .prepare(
        "SELECT id FROM users WHERE discord_id = ?"
      )
      .get(user.id);

    let userId;

    if (existingUser) {

      userId = existingUser.id;

      db.prepare(`
        UPDATE users
        SET username = ?, email = ?, avatar = ?
        WHERE id = ?
      `).run(
        user.username,
        user.email || "",
        user.avatar || "",
        userId
      );

    } else {

      const result = db.prepare(`
        INSERT INTO users
        (discord_id, username, email, avatar)
        VALUES (?, ?, ?, ?)
      `).run(
        user.id,
        user.username,
        user.email || "",
        user.avatar || ""
      );

      userId = result.lastInsertRowid;
    }


    /* SESSION */

    const sessionId =
      crypto.randomBytes(32).toString("hex");

    const expiresAt =
      new Date(
        Date.now() +
        7 * 24 * 60 * 60 * 1000
      ).toISOString();

    db.prepare(`
      INSERT INTO sessions
      (id, user_id, expires_at)
      VALUES (?, ?, ?)
    `).run(
      sessionId,
      userId,
      expiresAt
    );


    /* SESSION COOKIE */

    setCookie(
      res,
      "vequz_session",
      sessionId,
      {
        httpOnly: true,
        secure: true,
        sameSite: "Lax",
        maxAge: 7 * 24 * 60 * 60
      }
    );


    /* SUCCESS PAGE */

 // bisher:
// =========================
// LOGIN SUCCESS PAGE
// =========================

const MARKET_URL =
  process.env.MARKET_URL ||
  "https://vequz-market.vercel.app/";

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
  margin: 0;
  padding: 0;
}

html,
body {
  width: 100%;
  min-height: 100%;
  font-family: Arial, Helvetica, sans-serif;
  background: #000;
  color: #fff;
}

body {
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  overflow-x: hidden;
  background:
    radial-gradient(circle at center, rgba(255,255,0,.10), transparent 45%),
    #000;
}

.success-page {
  width: 100%;
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 35px 20px;
}

.box {
  width: 100%;
  max-width: 700px;
  text-align: center;
}

.badge {
  display: inline-block;
  padding: 13px 28px;
  border: 2px solid #ffff00;
  border-radius: 50px;
  color: #ffff00;
  font-size: 15px;
  font-weight: 800;
  letter-spacing: 4px;
  box-shadow: 0 0 25px rgba(255,255,0,.18);
  margin-bottom: 45px;
}

.check {
  width: 125px;
  height: 125px;
  margin: 0 auto 35px;
  border-radius: 50%;
  background: #ffff00;
  color: #000;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 75px;
  font-weight: 900;
  box-shadow:
    0 0 25px #ffff00,
    0 0 70px rgba(255,255,0,.55);
}

h1 {
  font-size: clamp(45px, 9vw, 90px);
  line-height: .9;
  font-weight: 900;
  letter-spacing: -4px;
  margin-bottom: 40px;
}

h1 span {
  color: #ffff00;
  text-shadow:
    0 0 10px #ffff00,
    0 0 35px rgba(255,255,0,.7);
}

.welcome {
  color: #aaa;
  font-size: 21px;
  margin-bottom: 8px;
}

.username {
  font-size: 31px;
  font-weight: 800;
  margin-bottom: 30px;
}

.line {
  width: 165px;
  height: 4px;
  background: #ffff00;
  margin: 0 auto 45px;
  box-shadow: 0 0 18px #ffff00;
}

.buttons {
  display: flex;
  flex-direction: column;
  gap: 18px;
}

.button {
  width: 100%;
  min-height: 76px;
  display: flex;
  align-items: center;
  justify-content: center;
  text-decoration: none;
  background: #ffff00;
  color: #000;
  border-radius: 18px;
  font-size: 21px;
  font-weight: 900;
  letter-spacing: .5px;
  transition: .2s ease;
  box-shadow: 0 0 25px rgba(255,255,0,.25);
}

.button:hover {
  transform: translateY(-3px);
  box-shadow:
    0 0 25px #ffff00,
    0 0 55px rgba(255,255,0,.45);
}

.button:active {
  transform: scale(.98);
}

.footer {
  margin-top: 55px;
  color: #666;
  font-size: 13px;
  font-weight: 800;
  letter-spacing: 4px;
}

@media (max-width: 600px) {

  .success-page {
    padding: 25px 18px;
  }

  .badge {
    font-size: 12px;
    padding: 11px 20px;
    letter-spacing: 3px;
    margin-bottom: 35px;
  }

  .check {
    width: 105px;
    height: 105px;
    font-size: 62px;
    margin-bottom: 28px;
  }

  h1 {
    font-size: 52px;
    letter-spacing: -3px;
    margin-bottom: 32px;
  }

  .welcome {
    font-size: 18px;
  }

  .username {
    font-size: 27px;
  }

  .line {
    margin-bottom: 35px;
  }

  .button {
    min-height: 68px;
    font-size: 18px;
    border-radius: 16px;
  }

  .footer {
    font-size: 10px;
    letter-spacing: 3px;
  }
}
</style>
</head>

<body>

<div class="success-page">

  <div class="box">

    <div class="badge">
      â DISCORD VERIFIED
    </div>

    <div class="check">
      â
    </div>

    <h1>
      LOGIN<br>
      <span>ERFOLGREICH</span>
    </h1>

    <div class="welcome">
      Willkommen zurÃ¼ck bei
    </div>

    <div class="username">
      ${escapeHtml(user.username)}
    </div>

    <div class="line"></div>

    <div class="buttons">

      <!-- HOMEPAGE -->
      <a
        class="button"
        href="${MARKET_URL}"
      >
        ZURÃCK ZUM MARKET â
      </a>

      <!-- DISCORD -->
      <a
        class="button"
        href="https://discord.gg/aWBdAPF4d"
        target="_blank"
        rel="noopener noreferrer"
      >
        JOIN DISCORD â
      </a>

    </div>

    <div class="footer">
      VEQUZ MARKET Â· PREMIUM Â· FAST Â· SECURE
    </div>

  </div>

</div>

</body>
</html>
`);


  } catch (error) {

    console.error(
      "Discord OAuth Error:",
      error
    );

    res.status(500).send(
      "Discord Login Fehler: " +
      error.message
    );
  }
});


/* CURRENT USER */

router.get("/me", (req, res) => {

  const cookies =
    parseCookies(req);

  if (!cookies.vequz_session) {

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

      users.avatar

    FROM sessions

    JOIN users
      ON users.id = sessions.user_id

    WHERE sessions.id = ?

  `).get(
    cookies.vequz_session
  );

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
    new Date(
      session.expires_at
    ).getTime() < Date.now()
  ) {

    db.prepare(
      "DELETE FROM sessions WHERE id = ?"
    ).run(
      session.id
    );

    clearCookie(
      res,
      "vequz_session"
    );

    return res.json({
      ok: true,
      loggedIn: false
    });
  }

  res.json({

    ok: true,

    loggedIn: true,

    user: {

      id: session.user_id,

      discordId:
        session.discord_id,

      username:
        session.username,

      email:
        session.email,

      avatar:
        session.avatar
    }
  });
});


/* LOGOUT */

router.get("/logout", (req, res) => {

  const cookies =
    parseCookies(req);

  if (cookies.vequz_session) {

    db.prepare(
      "DELETE FROM sessions WHERE id = ?"
    ).run(
      cookies.vequz_session
    );
  }

  clearCookie(
    res,
    "vequz_session"
  );

  res.json({

    ok: true,

    loggedOut: true

  });
});


module.exports = router;