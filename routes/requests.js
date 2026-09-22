const express = require("express");
const crypto = require("crypto");
const db = require("../database/db");

const router = express.Router();

router.post("/", (req, res) => {
  const {
    name,
    discord,
    email,
    type,
    message,
    priority
  } = req.body;

  if (!name || !type || !message) {
    return res.status(400).json({
      ok: false,
      error: "Name, Type und Message fehlen."
    });
  }

  const requestNumber =
    "VQ-" +
    crypto.randomBytes(4)
      .toString("hex")
      .toUpperCase();

  const result = db.prepare(`
    INSERT INTO requests
    (request_number, name, discord, email, type, message, priority)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).run(
    requestNumber,
    name,
    discord || "",
    email || "",
    type,
    message,
    priority || "normal"
  );

  res.json({
    ok: true,
    requestId: result.lastInsertRowid,
    requestNumber
  });
});

router.get("/", (req, res) => {
  const requests = db.prepare(`
    SELECT *
    FROM requests
    ORDER BY id DESC
  `).all();

  res.json({
    ok: true,
    requests
  });
});

module.exports = router;
