import express from "express";

const app = express();

function runQuery(sql: string) {
  return db.query(sql);
}

app.get("/search", (req, res) => {
  const q = req.query.q;
  return runQuery("SELECT * FROM products WHERE name = '" + q + "'");
});
