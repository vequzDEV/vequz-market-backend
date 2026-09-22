const express = require("express");

const router = express.Router();

router.get("/discord", (req, res) => {
  const clientId = process.env.DISCORD_CLIENT_ID;
  const redirectUri = process.env.DISCORD_REDIRECT_URI;

  if (!clientId || !redirectUri) {
    return res.status(503).json({
      ok: false,
      error: "Discord Login noch nicht eingerichtet."
    });
  }

  const params = new URLSearchParams({
    client_id: clientId,
    redirect_uri: redirectUri,
    response_type: "code",
    scope: "identify email"
  });

  res.redirect(
    "https://discord.com/oauth2/authorize?" +
    params.toString()
  );
});

router.get("/discord/callback", (req, res) => {
  if (!req.query.code) {
    return res.status(400).send(
      "Discord Code fehlt."
    );
  }

  res.send(
    "Discord Login Callback erreicht."
  );
});

module.exports = router;
