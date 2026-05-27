// VULNERABLE: SQL Injection examples (test fixture - DO NOT use in production)
const express = require('express');
const router = express.Router();

// A03: SQL injection via string concatenation
router.get('/user', (req, res) => {
  const userId = req.query.id;
  db.query("SELECT * FROM users WHERE id = " + userId, (err, rows) => {
    res.json(rows);
  });
});

// A03: SQL injection via template literal
router.post('/search', (req, res) => {
  const term = req.body.search;
  db.query(`SELECT * FROM products WHERE name LIKE '%${term}%'`, callback);
});

// A03: Command injection
const { exec } = require('child_process');
router.get('/ping', (req, res) => {
  const host = req.query.host;
  exec("ping -c 1 " + host, (err, stdout) => {
    res.send(stdout);
  });
});

// A02: Hardcoded secret
const API_KEY = "sk-1234567890abcdefghijklmnopqrstuvwxyz";
const DB_PASSWORD = "super_secret_password_123";

// A02: Weak crypto
const crypto = require('crypto');
const hash = crypto.createHash('md5').update(password).digest('hex');
