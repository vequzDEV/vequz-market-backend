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
        <title>VEQUZ MARKET · Login</title>

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
            background: #050505;
            color: white;
            font-family: Arial, sans-serif;
          }

          .box {
            width: min(90%, 500px);
            padding: 40px;
            text-align: center;
            border: 1px solid #ffff00;
            border-radius: 20px;
            background: #0b0b0b;
            box-shadow:
              0 0 30px rgba(255,255,0,.15),
              inset 0 0 30px rgba(255,255,0,.03);
          }

          .check {
            font-size: 55px;
            color: #ffff00;
            margin-bottom: 15px;
          }

          h1 {
            margin: 0 0 12px;
            color: #ffff00;
            font-size: 28px;
          }

          p {
            color: #aaa;
            margin-bottom: 25px;
          }

          strong {
            color: white;
          }

          a {
            display: inline-block;
            padding: 13px 22px;
            border-radius: 10px;
            background: #ffff00;
            color: #000;
            text-decoration: none;
            font-weight: 800;
          }
        </style>
      </head>

      <body>
        <div class="box">
          <div class="check">✓</div>

          <h1>LOGIN ERFOLGREICH</h1>

          <p>
            Willkommen bei VEQUZ MARKET,
            <strong>${escapeHtml(username)}</strong>.
          </p>

          <a href="/">ZURÜCK ZUM MARKET →</a>
        </div>
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
