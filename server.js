const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const sqlite3 = require('sqlite3').verbose();

const app = express();
const db = new sqlite3.Database('../database/to-do-app.db');
const secret = 'supersecretkey';

app.use(express.json());
app.use(require('cors')());

// Initialize DB
db.serialize(() => {
    db.run('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT)');
    db.run('CREATE TABLE IF NOT EXISTS tasks (user_id INTEGER, task TEXT, completed INTEGER)');
});

// Signup route
app.post('/signup', async (req, res) => {
    const { username, password } = req.body;
    const hash = await bcrypt.hash(password, 10);
    db.run('INSERT INTO users (username, password) VALUES (?, ?)', [username, hash], err => {
        if (err) return res.status(400).json({ error: 'Username exists' });
        res.status(201).json({ message: 'Signup successful' });
    });
});

// Login route
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
        if (err || !user || !(await bcrypt.compare(password, user.password)))
            return res.status(401).json({ error: 'Invalid credentials' });
        const token = jwt.sign({ id: user.id }, secret, { expiresIn: '1h' });
        res.json({ token });
    });
});

// Start server
app.listen(3000, () => console.log('Backend running on http://localhost:3000'));
