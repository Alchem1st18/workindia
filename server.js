const express = require('express');
const bodyParser = require('body-parser');
const mysql = require('mysql');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');

const app = express();
const port = 3000;

app.use(bodyParser.json());
app.use(express.json());

// MySQL connection
const db = mysql.createConnection({
    host: "localhost",
    user: "root",
    password: "Tssmanoj555^",
    database: "srikar"
});

// Secret key for JWT
const JWT_SECRET = 'your_jwt_secret';

// API key for admin routes
const ADMIN_API_KEY = 'your_admin_api_key';

// User registration
app.post('/api/signup', async (req, res) => {
  const { username, password, email } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    db.query(
      'INSERT INTO users (username, password, email) VALUES (?, ?, ?)',
      [username, hashedPassword, email],
      (error, results) => {
        if (error) throw error;
        res.json({
          status: "Account successfully created",
          status_code: 200,
          user_id: results.insertId
        });
      }
    );
  } catch (error) {
    res.status(500).json({ status: "Error creating account", status_code: 500 });
  }
});

// User login
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  db.query(
    'SELECT * FROM users WHERE username = ?',
    [username],
    async (error, results) => {
      if (error) throw error;
      if (results.length > 0) {
        const user = results[0];
        if (await bcrypt.compare(password, user.password)) {
          const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET);
          res.json({
            status: "Login successful",
            status_code: 200,
            user_id: user.id,
            access_token: token
          });
        } else {
          res.status(401).json({
            status: "Incorrect username/password provided. Please retry",
            status_code: 401
          });
        }
      } else {
        res.status(401).json({
          status: "Incorrect username/password provided. Please retry",
          status_code: 401
        });
      }
    }
  );
});

// Middleware to check admin API key
const checkAdminApiKey = (req, res, next) => {
  const apiKey = req.headers['x-api-key'];
  if (apiKey && apiKey === ADMIN_API_KEY) {
    next();
  } else {
    res.status(403).json({ status: "Unauthorized", status_code: 403 });
  }
};

// Create a new short (admin only)
app.post('/api/shorts/create', checkAdminApiKey, (req, res) => {
  const { category, title, author, publish_date, content, actual_content_link, image } = req.body;
  db.query(
    'INSERT INTO shorts (category, title, author, publish_date, content, actual_content_link, image, upvotes, downvotes) VALUES (?, ?, ?, ?, ?, ?, ?, 0, 0)',
    [category, title, author, publish_date, content, actual_content_link, image],
    (error, results) => {
      if (error) throw error;
      res.json({
        message: "Short added successfully",
        short_id: results.insertId,
        status_code: 200
      });
    }
  );
});

// Get shorts feed
app.get('/api/shorts/feed', (req, res) => {
  db.query(
    'SELECT * FROM shorts ORDER BY publish_date DESC, upvotes DESC LIMIT 20',
    (error, results) => {
      if (error) throw error;
      res.json(results);
    }
  );
});

// Middleware to verify JWT
const verifyToken = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.status(403).json({ status: "No token provided", status_code: 403 });
  
  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) return res.status(401).json({ status: "Unauthorized", status_code: 401 });
    req.userId = decoded.id;
    next();
  });
};

// Get filtered shorts
app.get('/api/shorts/filter', verifyToken, (req, res) => {
  const { category, publish_date, upvote, title, keyword, author } = req.query;
  let query = 'SELECT * FROM shorts WHERE 1=1';
  const params = [];

  if (category) {
    query += ' AND category = ?';
    params.push(category);
  }
  if (publish_date) {
    query += ' AND publish_date >= ?';
    params.push(publish_date);
  }
  if (upvote) {
    query += ' AND upvotes > ?';
    params.push(parseInt(upvote));
  }
  if (title) {
    query += ' AND title LIKE ?';
    params.push(%${title}%);
  }
  if (keyword) {
    query += ' AND (title LIKE ? OR content LIKE ?)';
    params.push(%${keyword}%);
    params.push(%${keyword}%);
  }
  if (author) {
    query += ' AND author LIKE ?';
    params.push(%${author}%);
  }

  query += ' ORDER BY publish_date DESC, upvotes DESC';

  db.query(query, params, (error, results) => {
    if (error) throw error;
    if (results.length > 0) {
      res.json(results);
    } else {
      res.status(400).json({
        status: "No short matches your search criteria",
        status_code: 400
      });
    }
  });
});

app.listen(port, () => {
  console.log(Server running on port ${port});
});
