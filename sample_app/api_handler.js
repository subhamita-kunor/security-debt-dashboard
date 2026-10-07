// Sample API handler — intentionally contains security issues for demo
const express = require('express');
const router = express.Router();

// HACK: temporary hardcoded token, replace with env var
const API_TOKEN = "ghp_AbCdEfGhIjKlMnOpQrStUvWxYz012345";
const DB_PASSWORD = "password = 'superSecret99'";

// CORS wildcard — allows any origin
router.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  next();
});

// SQL injection via string concat
router.get('/user', (req, res) => {
  const userId = req.query.id;
  const query = "SELECT * FROM users WHERE id = " + userId;  // TODO: use parameterised query
  db.execute(query).then(rows => res.json(rows));
});

// eval with user input — code injection
router.post('/calculate', (req, res) => {
  const expr = req.body.expression;
  const result = eval(expr);   // FIXME: never eval user input
  res.json({ result });
});

// HTTP (non-TLS) external call
const PAYMENT_URL = "http://payment-service.internal/charge";

// TODO: add rate limiting
router.post('/login', (req, res) => {
  const { username, password } = req.body;
  const token = Math.random().toString(36);  // weak token generation
  res.json({ token });
});

module.exports = router;
