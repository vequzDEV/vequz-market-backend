require("dotenv").config();

const express = require("express");
const cors = require("cors");
const path = require("path");

require("./database/db");

const requests = require("./routes/requests");
const products = require("./routes/products");
const users = require("./routes/users");
const auth = require("./routes/auth");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

app.get("/api/health", (req, res) => {
  res.json({
    ok: true,
    status: "online",
    name: "VEQUZ MARKET"
  });
});

app.use("/api/requests", requests);
app.use("/api/products", products);
app.use("/api/users", users);
app.use("/api/auth", auth);

app.listen(PORT, () => {
  console.log("VEQUZ MARKET BACKEND ONLINE");
  console.log(`http://localhost:${PORT}`);
});