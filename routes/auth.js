const express = require("express");
const crypto = require("crypto");
const db = require("../database/db");

const router = express.Router();

const CLIENT_ID = process.env.DISCORD_CLIENT_ID;
const CLIENT_SECRET = process.env.DISCORD_CLIENT_SECRET;
const REDIRECT_URI = process.env.DISCORD_REDIRECT_URI;

function parseCookies(req) {
  const cookies = {};

  const header = req.headers.cookie;
  if (!header) return cookies;

  header.split(";").forEach((cookie) => {
    const [name, ...rest] = cookie.trim().split("=");

    if (!name) return;

    cookies[name] = decodeURIComponent(
      rest.join("=")
    );
  });

  return cookies;
}

function setCookie(res, name, value, maxAge) {
  res.setHeader(
    "Set-Cookie",
    `${name}=${encodeURIComponent(value)}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${maxAge}`
  );
}

/*
================================
DISCORD LOGIN START
================================
*/

router.get("/discord", (req, res) => {

  if (!CLIENT_ID || !CLIENT_SECRET || !REDIRECT_URI) {
    return res.status(503).json({
      ok: false,
      error: "Discord Login noch nicht eingerichtet."
    });
  }

  const state = crypto
    .randomBytes(32)
    .toString("hex");

  setCookie(
    res,
    "vequz_oauth_state",
    state,
    600
  );

  const params = new URLSearchParams({
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    response_type: "code",
    scope: "identify email",
    state
  });

  res.redirect(
    "https://discord.com/oauth2/authorize?" +
    params.toString()
  );
});


/*
================================
DISCORD CALLBACK
================================
*/

router.get("/discord/callback", async (req, res) => {

  try {

    const { code, state } = req.query;

    if (!code) {
      return res.status(400).send(
        "Discord Code fehlt."
      );
    }

    const cookies = parseCookies(req);

    const savedState =
      cookies.vequz_oauth_state;

    if (
      !state ||
      !savedState ||
      state !== savedState
    ) {
      return res.status(403).send(
        "Ungültige Discord Anmeldung."
      );
    }

    /*
    ================================
    CODE → ACCESS TOKEN
    ================================
    */

    const tokenResponse = await fetch(
      "https://discord.com/api/oauth2/token",
      {
        method: "POST",

        headers: {
          "Content-Type":
            "application/x-www-form-urlencoded"
        },

        body: new URLSearchParams({
          client_id: CLIENT_ID,
          client_secret: CLIENT_SECRET,
          grant_type:
            "authorization_code",
          code,
          redirect_uri: REDIRECT_URI
        })
      }
    );

    const tokenData =
      await tokenResponse.json();

    if (
      !tokenResponse.ok ||
      !tokenData.access_token
    ) {

      console.error(
        "Discord Token Fehler:",
        tokenData
      );

      return res.status(401).send(
        "Discord Login konnte nicht abgeschlossen werden."
      );
    }

    /*
    ================================
    DISCORD USER LADEN
    ================================
    */

    const userResponse = await fetch(
      "https://discord.com/api/users/@me",
      {
        headers: {
          Authorization:
            `Bearer ${tokenData.access_token}`
        }
      }
    );

    const discordUser =
      await userResponse.json();

    if (!userResponse.ok) {

      console.error(
        "Discord User Fehler:",
        discordUser
      );

      return res.status(401).send(
        "Discord Benutzer konnte nicht geladen werden."
      );
    }

    /*
    ================================
    USER IN DATABASE SPEICHERN
    ================================
    */

    const username =
      discordUser.global_name ||
      discordUser.username ||
      "Discord User";

    const email =
      discordUser.email || "";

    const avatar =
      discordUser.avatar || "";

    const user = db.prepare(`
      INSERT INTO users
      (
        discord_id,
        username,
        email,
        avatar
      )
      VALUES (?, ?, ?, ?)

      ON CONFLICT(discord_id)
      DO UPDATE SET
        username = excluded.username,
        email = excluded.email,
        avatar = excluded.avatar

      RETURNING *
    `).get(
      discordUser.id,
      username,
      email,
      avatar
    );

    /*
    ================================
    SESSION ERSTELLEN
    ================================
    */

    const sessionId =
      crypto.randomBytes(32).toString("hex");

    const expiresAt =
      new Date(
        Date.now() +
        1000 * 60 * 60 * 24 * 7
      ).toISOString();

    db.prepare(`
      INSERT INTO sessions
      (
        id,
        user_id,
        expires_at
      )
      VALUES (?, ?, ?)
    `).run(
      sessionId,
      user.id,
      expiresAt
    );

    /*
    ================================
    LOGIN COOKIE
    ================================
    */

    setCookie(
      res,
      "vequz_session",
      sessionId,
      60 * 60 * 24 * 7
    );

    /*
    ================================
    OAUTH STATE LÖSCHEN
    ================================
    */

    setCookie(
      res,
      "vequz_oauth_state",
      "",
      0
    );

    /*
    ================================
    ERFOLGREICH
    ================================
    */

    res.send(`
      <!DOCTYPE html>

      <html lang="de">

      <head>
        <meta charset="UTF-8">

        <meta
          name="viewport"
          content="width=device-width, initial-scale=1.0"
        >

        <title>VEQUZ MARKET</title>

        <style>

          body {
            margin: 0;
            min-height: 100vh;

            display: flex;
            align-items: center;
            justify-content: center;

            background: #080808;
            color: white;

            font-family: Arial, sans-serif;
          }

          .box {
            width: min(90%, 500px);

            padding: 40px 30px;

            text-align: center;

            border: 1px solid #333;
            border-radius: 18px;

            background: #111;

            box-shadow:
              0 0 40px rgba(255,255,0,.12);
          }

          h1 {
            margin: 0 0 15px;

            color: #ffff00;

            font-size: 32px;
          }

          p {
            color: #bbb;
            line-height: 1.6;
          }

          .user {
            margin-top: 25px;

            padding: 15px;

            border-radius: 12px;

            background: #191919;

            color: #fff;
          }

        </style>
      </head>

      <body>

        <div class="box">

          <h1>✓ LOGIN ERFOLGREICH</h1>

          <p>
            Dein Discord Account wurde erfolgreich
            mit VEQUZ MARKET verbunden.
          </p>

          <div class="user">
            ${username}
          </div>

          <p>
            Session gültig für 7 Tage.
          </p>

        </div>

      </body>

      </html>
    `);

  } catch (error) {

    console.error(
      "Discord OAuth Fehler:",
      error
    );

    res.status(500).send(
      "Interner Fehler beim Discord Login."
    );
  }
});


/*
================================
AKTUELL EINGELOGGTER USER
================================
*/

router.get("/me", (req, res) => {

  const cookies = parseCookies(req);

  const sessionId =
    cookies.vequz_session;

  if (!sessionId) {
    return res.status(401).json({
      ok: false,
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
  `).get(sessionId);

  if (!session) {
    return res.status(401).json({
      ok: false,
      loggedIn: false
    });
  }

  if (
    new Date(session.expires_at) <=
    new Date()
  ) {

    db.prepare(`
      DELETE FROM sessions
      WHERE id = ?
    `).run(sessionId);

    return res.status(401).json({
      ok: false,
      loggedIn: false
    });
  }

  res.json({
    ok: true,
    loggedIn: true,

    user: {
      id: session.user_id,
      discord_id: session.discord_id,
      username: session.username,
      email: session.email,
      avatar: session.avatar
    }
  });
});


/*
================================
LOGOUT
================================
*/

router.get("/logout", (req, res) => {

  const cookies = parseCookies(req);

  const sessionId =
    cookies.vequz_session;

  if (sessionId) {

    db.prepare(`
      DELETE FROM sessions
      WHERE id = ?
    `).run(sessionId);
  }

  setCookie(
    res,
    "vequz_session",
    "",
    0
  );

  res.json({
    ok: true,
    loggedOut: true
  });
});


module.exports = router;
