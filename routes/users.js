const express = require("express");
const db = require("../database/db");

const router = express.Router();

router.get("/", (req, res) => {
  const users = db.prepare(`
    SELECT
      id,
      discord_id,
      username,
      email,
      avatar,
      created_at
    FROM users
    ORDER BY id DESC
  `).all();

  res.json({
    ok: true,
    users
  });
});

module.exports = router;
