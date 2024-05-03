const express = require("express");
const app = express();
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const sqlite3 = require("sqlite3");
const { open } = require("sqlite");
const path = require("path");

app.use(cors());
app.use(express.json());

const dbPath = path.join(__dirname, "database.db");
let db = null;

// Connecting database to server
const initializeServerAndDatabase = async () => {
  try {
    db = await open({
      filename: dbPath,
      driver: sqlite3.Database,
    });
    app.listen(3000, () => {
      console.log(`Server is running on http://localhost:3000/`);
    });
  } catch (e) {
    console.log(`DB Error : ${e.message}`);
  }
};

initializeServerAndDatabase();

// Authentication user middleware
const authenticateToken = (request, response, next) => {
  const token = request.headers.authorization;
  console.log(token);
  if (!token) {
    return response.status(401).send("No Token from user");
  }
  const tokenParts = token.split(" ");
  const jwtToken = tokenParts[1];
  jwt.verify(jwtToken, "Token", (err, payload) => {
    if (err) {
      console.error("Token Verification Error:", err);
      return response.status(403).send("Unauthorized - Invalid token");
    }
    request.user = payload; // Storing  payload user information in request object
    next();
  });
};

// Registering new user
app.post("/register", async (request, response) => {
  const { name, password, phonenumber } = request.body;

  try {
    const dbUser = await db.get(`SELECT * FROM users WHERE name=?`, [name]);
    if (dbUser !== undefined) {
      return response.status(409).send("name Already Exists");
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const createNewUserQuery = `
            INSERT INTO users(name,  password,phonenumber)
            VALUES (?, ?, ?);
        `;
    await db.run(createNewUserQuery, [name, hashedPassword, phonenumber]);
    response.status(201).send("add user Successfully");
  } catch (error) {
    console.log("Error registering user:", error.message);
    response.status(500).send("Internal Server Error");
  }
});

// Login with user credentials
app.post("/login", async (request, response) => {
  const { name, password } = request.body;
  try {
    const dbUser = await db.get(`SELECT * FROM users WHERE name = ?`, [name]);
    if (!dbUser) {
      return response.status(400).send("User Not Found");
    }

    const isPasswordSame = await bcrypt.compare(password, dbUser.password);
    if (!isPasswordSame) {
      return response.status(400).send("Password Not Same");
    }

    const payload = {
      id: dbUser.id,
      name: dbUser.name,
    };

    const jwtToken = jwt.sign(payload, "Token");
    response.status(200).send({ jwtToken, isAdmin: dbUser.isAdmin });
  } catch (error) {
    console.log("Error logging in:", error.message);
    response.status(500).send("Internal Server Error");
  }
});

// Getting all tasks
app.post("/tasks", authenticateToken, async (request, response) => {
  const dbUser = await db.get(`SELECT * FROM users WHERE name = ?`, [
    request.user.name,
  ]);

  console.log(dbUser);
  const { task, description } = request.body;
  try {
    const createNewTaskQuery = `
            INSERT INTO tasks(task, description,  user_id)
            VALUES (?, ?, ?);
        `;
    await db.run(createNewTaskQuery, [task, description, getid]);
    response.status(201).send("Task Created Successfully");
  } catch (error) {
    console.log("Error creating task:", error.message);
    response.status(500).send("Internal Server Error");
  }
});

// Getting all users
app.get("/users", authenticateToken, async (request, response) => {
  try {
    const getAllUsersQuery = `SELECT name FROM users;`;
    const userList = await db.all(getAllUsersQuery);
    response.send(userList);
  } catch (error) {
    console.log("Error retrieving users:", error.message);
    response.status(500).send("Internal Server Error");
  }
});

// Deleting user only - admin
app.delete("/users/:userId", authenticateToken, async (request, response) => {
  const { userId } = request.params;
  try {
    const dbUser = await db.get(`SELECT * FROM users WHERE name = ?`, [
      request.user.name,
    ]);

    const deleteQuery = `DELETE FROM users WHERE id = ?`;
    await db.run(deleteQuery, [userId]);
    response.send("Successfully Deleted");
  } catch (error) {
    console.log("Error deleting task:", error.message);
    response.status(500).send("Internal Server Error");
  }
});

// Getting all tasks
app.get("/tasks", authenticateToken, async (request, response) => {
  try {
    const getAllTasksQuery = `SELECT * FROM tasks;`;
    const taskList = await db.all(getAllTasksQuery);
    response.json(taskList);
  } catch (error) {
    console.log("Error retrieving tasks:", error.message);
    response.status(500).send("Internal Server Error");
  }
});

app.get("/tasks/:taskId", authenticateToken, async (request, response) => {
  const { taskId } = request.params;
  try {
    const getTaskQuery = `SELECT * FROM tasks WHERE id = ?`;
    const result = await db.get(getTaskQuery, [taskId]);
    response.send(result);
  } catch (error) {
    console.log("Error retrieving task:", error.message);
    response.status(500).send("Internal Server Error");
  }
});

// Updating specific task with task id
app.put("/tasks/:taskId", authenticateToken, async (request, response) => {
  const { taskId } = request.params;
  const { task, description } = request.body;
  try {
    const updateTaskQuery = `
            UPDATE tasks SET
            task=?,
            description=?,
            WHERE id=?
        `;
    await db.run(updateTaskQuery, [task, description, taskId]);
    response.send("Task Updated");
  } catch (error) {
    console.log("Error updating task:", error.message);
    response.status(500).send("Internal Server Error");
  }
});

// Deleting specific task with task id
app.delete("/tasks/:taskId", authenticateToken, async (request, response) => {
  const { taskId } = request.params;
  try {
    const deleteQuery = `DELETE FROM tasks WHERE id = ?`;
    await db.run(deleteQuery, [taskId]);
    response.send("Successfully Deleted");
  } catch (error) {
    console.log("Error deleting task:", error.message);
    response.status(500).send("Internal Server Error");
  }
});

app.get("/", (request, response) => {
  response.send("succses");
});
