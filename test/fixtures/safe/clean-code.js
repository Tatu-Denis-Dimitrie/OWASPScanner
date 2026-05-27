// SAFE: Properly secured code examples (test fixture)
const express = require('express');
const router = express.Router();
const crypto = require('crypto');

// Safe: parameterized query
router.get('/user', authenticate, (req, res) => {
  const userId = req.query.id;
  db.query("SELECT * FROM users WHERE id = ?", [userId], (err, rows) => {
    if (err) {
      console.error('Database error');
      return res.status(500).json({ error: 'Internal server error' });
    }
    res.json(rows);
  });
});

// Safe: config from environment variables
const config = {
  dbPassword: process.env.DB_PASSWORD,
  jwtSecret: process.env.JWT_SECRET,
};

// Safe: strong crypto
const hash = crypto.createHash('sha256').update(data).digest('hex');
const token = crypto.randomBytes(32).toString('hex');

// Safe: textContent instead of innerHTML
function renderUsername(username) {
  const el = document.createElement('span');
  el.textContent = username;
  return el;
}
