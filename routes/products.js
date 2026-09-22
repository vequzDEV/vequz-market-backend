const express = require("express");
const db = require("../database/db");

const router = express.Router();

router.get("/", (req, res) => {
  const products = db.prepare(`
    SELECT *
    FROM products
    WHERE status = 'active'
    ORDER BY id DESC
  `).all();

  res.json({
    ok: true,
    products
  });
});

router.post("/", (req, res) => {
  const {
    name,
    slug,
    description,
    category,
    price_cents
  } = req.body;

  if (!name || !slug) {
    return res.status(400).json({
      ok: false,
      error: "Name und Slug fehlen."
    });
  }

  try {
    const result = db.prepare(`
      INSERT INTO products
      (name, slug, description, category, price_cents)
      VALUES (?, ?, ?, ?, ?)
    `).run(
      name,
      slug,
      description || "",
      category || "other",
      Number(price_cents) || 0
    );

    res.json({
      ok: true,
      productId: result.lastInsertRowid
    });

  } catch {
    res.status(409).json({
      ok: false,
      error: "Produkt existiert bereits."
    });
  }
});

module.exports = router;
