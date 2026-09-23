const express = require("express");
const crypto = require("crypto");
const db = require("../database/db");

const router = express.Router();

const CLIENT_ID = process.env.DISCORD_CLIENT_ID;
const CLIENT_SECRET = process.env.DISCORD_CLIENT_SECRET;
const REDIRECT_URI = process.env.DISCORD_REDIRECT_URI;

// ==============================
// COOKIE HELPERS
// ==============================

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
          part.slice(0, index),
          decodeURIComponent(part.slice(index + 1))
        ];
      })
  );
}

function setCookie(res, name, value, options = {}) {
  let cookie = `${name}=${encodeURIComponent(value)}`;

  if (options.maxAge !== undefined) {
    cookie += `; Max-Age=${options.maxAge}`;
  }

  if (options.httpOnly !== false) {
    cookie += "; HttpOnly";
  }

  if (options.secure !== false) {
    cookie += "; Secure";
  }

  cookie += `; SameSite=${options.sameSite || "Lax"}`;

  if (options.path) {
    cookie += `; Path=${options.path}`;
  }

  res.append("Set-Cookie", cookie);
}

function clearCookie(res, name) {
  res.append(
    "Set-Cookie",
    `${name}=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=Lax`
  );
}

// ==============================
// HTML ESCAPE
// ==============================

function escapeHtml(value) {
  return String(value || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

// ==============================
// DEBUG
// ==============================

router.get("/debug", (req, res) => {
  res.json({
    ok: true,
    discordClientId: Boolean(process.env.DISCORD_CLIENT_ID),
    discordClientSecret: Boolean(process.env.DISCORD_CLIENT_SECRET),
    discordRedirectUri: Boolean(process.env.DISCORD_REDIRECT_URI),
    redirectUri: process.env.DISCORD_REDIRECT_URI || null,
    nodeEnv: process.env.NODE_ENV || null
  });
});

// ==============================
// DISCORD LOGIN
// ==============================

router.get("/discord", (req, res) => {
  if (!CLIENT_ID || !CLIENT_SECRET || !REDIRECT_URI) {
    return res.status(503).json({
      ok: false,
      error: "Discord Login noch nicht eingerichtet.",
      discordClientId: Boolean(CLIENT_ID),
      discordClientSecret: Boolean(CLIENT_SECRET),
      discordRedirectUri: Boolean(REDIRECT_URI)
    });
  }

  const state = crypto.randomBytes(32).toString("hex");

  setCookie(res, "oauth_state", state, {
    maxAge: 600,
    path: "/"
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

// ==============================
// DISCORD CALLBACK
// ==============================

router.get("/discord/callback", async (req, res) => {
  try {
    const { code, state } = req.query;

    if (!code) {
      return res.status(400).send("Discord Code fehlt.");
    }

    const cookies = parseCookies(req);

    if (!state || !cookies.oauth_state || state !== cookies.oauth_state) {
      return res.status(400).send("Ungültiger OAuth State.");
    }

    if (!CLIENT_ID || !CLIENT_SECRET || !REDIRECT_URI) {
      return res.status(503).send("Discord Login ist nicht konfiguriert.");
    }

    // ==========================
    // CODE → ACCESS TOKEN
    // ==========================

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

    if (!tokenResponse.ok || !tokenData.access_token) {
      console.error("Discord token error:", tokenData);

      return res.status(401).send(
        "Discord Login fehlgeschlagen: Token konnte nicht erstellt werden."
      );
    }

    // ==========================
    // DISCORD USER ABFRAGEN
    // ==========================

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
      console.error("Discord user error:", discordUser);

      return res.status(401).send(
        "Discord Benutzer konnte nicht geladen werden."
      );
    }

    // ==========================
    // USER SPEICHERN / AKTUALISIEREN
    // ==========================

    const username =
      discordUser.global_name ||
      discordUser.username ||
      "Discord User";

    const avatar = discordUser.avatar
      ? `https://cdn.discordapp.com/avatars/${discordUser.id}/${discordUser.avatar}.png`
      : "";

    let user = db
      .prepare(
        `SELECT * FROM users WHERE discord_id = ?`
      )
      .get(discordUser.id);

    if (!user) {
      const result = db
        .prepare(
          `
          INSERT INTO users
          (discord_id, username, email, avatar)
          VALUES (?, ?, ?, ?)
          `
        )
        .run(
          discordUser.id,
          username,
          discordUser.email || "",
          avatar
        );

      user = db
        .prepare(
          `SELECT * FROM users WHERE id = ?`
        )
        .get(result.lastInsertRowid);
    } else {
      db.prepare(
        `
        UPDATE users
        SET username = ?,
            email = ?,
            avatar = ?
        WHERE id = ?
        `
      ).run(
        username,
        discordUser.email || "",
        avatar,
        user.id
      );

      user = db
        .prepare(
          `SELECT * FROM users WHERE id = ?`
        )
        .get(user.id);
    }

    // ==========================
    // SESSION ERSTELLEN
    // ==========================

    const sessionId = crypto.randomBytes(32).toString("hex");

    const expiresAt = new Date(
      Date.now() + 7 * 24 * 60 * 60 * 1000
    ).toISOString();

    db.prepare(
      `
      INSERT INTO sessions
      (id, user_id, expires_at)
      VALUES (?, ?, ?)
      `
    ).run(
      sessionId,
      user.id,
      expiresAt
    );

    // ==========================
    // SESSION COOKIE
    // ==========================

    setCookie(res, "vequz_session", sessionId, {
      maxAge: 7 * 24 * 60 * 60,
      path: "/"
    });

    clearCookie(res, "oauth_state");

    // ==========================
    // SUCCESS PAGE
    // ==========================

res.send(`

<!DOCTYPE html>
<html lang="de">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">

<title>VEQUZ MARKET — Login erfolgreich</title>

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
      ✓ DISCORD VERIFIED
    </div>

    <div class="check">
      ✓
    </div>

    <h1>
      LOGIN
      <span>ERFOLGREICH</span>
    </h1>

    <div class="welcome-text">
      Willkommen zurück bei
    </div>

    <div class="username">
      VEQUZ MARKET

    </div>

    <div class="divider"></div>

    <a class="enter" href="/">
      ZURÜCK ZUM MARKET →
    </a>

    <div class="brand">
      VEQUZ MARKET · PREMIUM · FAST · SECURE
    </div>

  </div>

</section>

</body>
</html>

`);

  } catch (error) {
    console.error("Discord OAuth error:", error);

    res.status(500).send(
      "Interner Fehler beim Discord Login."
    );
  }
});

// ==============================
// AKTUELLER USER
// ==============================

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

    const session = db
      .prepare(
        `
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
        `
      )
      .get(sessionId);

    if (!session) {
      return res.json({
        ok: true,
        loggedIn: false
      });
    }

    if (
      new Date(session.expires_at).getTime() <= Date.now()
    ) {
      db.prepare(
        `DELETE FROM sessions WHERE id = ?`
      ).run(sessionId);

      clearCookie(res, "vequz_session");

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
        discordId: session.discord_id,
        username: session.username,
        email: session.email,
        avatar: session.avatar
      }
    });

  } catch (error) {
    console.error("Session error:", error);

    res.status(500).json({
      ok: false,
      error: "Session konnte nicht geladen werden."
    });
  }
});

// ==============================
// LOGOUT
// ==============================

router.get("/logout", (req, res) => {
  const cookies = parseCookies(req);
  const sessionId = cookies.vequz_session;

  if (sessionId) {
    db.prepare(
      `DELETE FROM sessions WHERE id = ?`
    ).run(sessionId);
  }

  clearCookie(res, "vequz_session");

  res.json({
    ok: true,
    loggedOut: true
  });
});

// ==============================
// EXPORT
// ==============================

module.exports = router;
