const express = require("express");
const app = express();
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const sqlite3 = require("sqlite3");
const { open } = require("sqlite");
const path = require("path");

app.use(express.json());
app.use(cors());
const dbpath = path.join(__dirname, "database.db");
let db=null 

//conect db and server
const indbtosrver = async () => {
  try {
    db = await open({
      filename: dbpath,
      driver: sqlite3.Database,
    });
    app.listen(3000, () => {
      console.log("erver is running in 3000localhost");
    });
  } catch (e) {
    console.log(`db has error : ${e.messege}`);
  }
};
indbtosrver();

//new user adding

app.post("/rigister", async (request, response) => {
  try {
    const { name, password, phonenumber } = request.body;

    const checkuser = await db.get(`SELECT * FROM users WHERE name = ?`, [
      name,
    ]);

    if (checkuser !== undefined) {
      return response.status(400).send("useralreadyexist");
    }
    const haspasword = await bcrypt.hash(password, 10);
    await db.run(
      `INSERT INTO users (name,password,phonenumber) VALUES (?,?,?) `,
      [name, haspasword, phonenumber]
    );
    console.log("rigister sucess");
    response.status(200).send("new user add");
  } catch (err) {
    console.log(err.messege);
    response.status(400).send(`error has :${err.messege}`);
  }
});

//checkvalid user
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) {
      return res.sendStatus(401); // Unauthorized
  }

  jwt.verify(token, 'your-secret-key', (err, user) => {
      if (err) {
          return res.sendStatus(403); // Forbidden
      }
      req.user = user;
      next();
  });
}

// Create task
app.post('/tasks', authenticateToken, (req, res) => {
  const { title, description } = req.body;
  const userId = req.user.userId;
  const sql = `INSERT INTO tasks (title, description, user_id) VALUES (?, ?, ?)`;
  db.run(sql, [title, description, userId], function(err) {
      if (err) {
          return res.status(500).json({ error: err.message });
      }
      res.json({
          message: 'Task created successfully',
          taskId: this.lastID
      });
  });
});

// Read all tasks
app.get('/tasks', authenticateToken, (req, res) => {
  const userId = req.user.userId;
  const sql = `SELECT * FROM tasks WHERE user_id = ?`;
  db.all(sql, [userId], (err, rows) => {
      if (err) {
          return res.status(500).json({ error: err.message });
      }
      res.json(rows);
  });
});

// Read task by ID
app.get('/tasks/:id', authenticateToken, (req, res) => {
  const userId = req.user.userId;
  const taskId = req.params.id;
  const sql = `SELECT * FROM tasks WHERE id = ? AND user_id = ?`;
  db.get(sql, [taskId, userId], (err, row) => {
      if (err) {
          return res.status(500).json({ error: err.message });
      }
      if (!row) {
          return res.status(404).json({ message: 'Task not found' });
      }
      res.json(row);
  });
});

// Update task by ID
app.put('/tasks/:id', authenticateToken, (req, res) => {
  const userId = req.user.userId;
  const taskId = req.params.id;
  const { title, description } = req.body;
  const sql = `UPDATE tasks SET title = ?, description = ? WHERE id = ? AND user_id = ?`;
  db.run(sql, [title, description, taskId, userId], function(err) {
      if (err) {
          return res.status(500).json({ error: err.message });
      }
      res.json({ message: 'Task updated successfully' });
  });
});

// Delete task by ID
app.delete('/tasks/:id', authenticateToken, (req, res) => {
  const userId = req.user.userId;
  const taskId = req.params.id;
  const sql = `DELETE FROM tasks WHERE id = ? AND user_id = ?`;
  db.run(sql, [taskId, userId], function(err) {
      if (err) {
          return res.status(500).json({ error: err.message });
      }
      res.json({ message: 'Task deleted successfully' });
  });
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const sql = `SELECT id FROM users WHERE username = ? AND password = ?`;
  db.get(sql, [username, password], (err, row) => {
      if (err) {
          return res.status(400).json({ error: err.message });
      }
      if (!row) {
          return res.status(401).json({ message: 'Invalid username or password' });
      }
      const userId = row.id;
      const token = jwt.sign({ userId, username }, 'your-secret-key');
      res.json({ token });
  });
});









app.get("/", (request, response) => {
  response.send("server is running");
});
