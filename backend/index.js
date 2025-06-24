require('dotenv').config();

const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const { body, validationResult } = require('express-validator');
const rateLimit = require('express-rate-limit');

const app = express();
const pool = new Pool({ connectionString: process.env.DATABASE_URL });
const jwtSecret = process.env.JWT_SECRET;

// Rate Limiters
const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: 'Too many requests from this IP, please try again later.'
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: 'Too many login/register attempts. Please try again in 15 minutes.'
});

// Middleware
app.use(express.json());
app.use(generalLimiter);

// JWT Auth Middleware
function authMiddleware(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader?.split(' ')[1];
  if (!token) return res.sendStatus(401);

  try {
    const decoded = jwt.verify(token, jwtSecret);
    req.user = decoded;
    next();
  } catch {
    res.sendStatus(403);
  }
}

// Validators
const registerValidators = [
  body('username')
    .isAlphanumeric().withMessage('Username must be alphanumeric')
    .isLength({ min: 5 }).withMessage('Username must be at least 5 characters')
    .trim().escape(),
  body('password')
    .isLength({ min: 5 }).withMessage('Password must be at least 5 characters')
];

const loginValidators = [
  body('username').trim().notEmpty().withMessage('Username required'),
  body('password').notEmpty().withMessage('Password required')
];

// REGISTER
app.post('/register', authLimiter, registerValidators, async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  const { username, password } = req.body;

  try {
    const existingUser = await pool.query('SELECT 1 FROM users WHERE username = $1', [username]);
    if (existingUser.rowCount > 0) return res.status(400).send('Username already exists');

    const hashedPassword = await bcrypt.hash(password, 10);
    await pool.query(
      'INSERT INTO users (username, password) VALUES ($1, $2)',
      [username, hashedPassword]
    );

    res.status(201).send('User registered');
  } catch (err) {
    console.error(err);
    res.status(500).send('Error creating user');
  }
});

// LOGIN
app.post('/login', authLimiter, loginValidators, async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  const { username, password } = req.body;

  try {
    const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    if (result.rows.length === 0) return res.status(400).send('Invalid credentials');

    const user = result.rows[0];
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(400).send('Invalid credentials');

    const token = jwt.sign({ userId: user.id }, jwtSecret, { expiresIn: '1h' });

    res.json({ message: 'Login successful', token });
  } catch (err) {
    console.error(err);
    res.status(500).send('Error logging in');
  }
});

// Protected Route
app.get('/welcome', authMiddleware, (req, res) => {
  res.send(`Welcome, user ${req.user.userId}`);
});

// Start Server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
