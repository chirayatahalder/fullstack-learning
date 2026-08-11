require("dotenv").config();
console.log('DB URL loaded:', process.env.DATABASE_URL);

const { PrismaClient } = require("./generated/prisma");
const { PrismaPg } = require("@prisma/adapter-pg");

const adapter = new PrismaPg({ connectionString: process.env.DATABASE_URL });
const prisma = new PrismaClient({ adapter });

const express = require("express");
const { Pool } = require("pg");

const app = express();
app.use(express.json());

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer")) {
    return res.status(401).json({ error: "No token provided" });
  }

  const token = authHeader.split(" ")[1];

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ error: "Invalid or expired token" });
  }
}

function requireRole(role) {
  return (req, res, next) => {
    if (req.user.role !== role) {
      return res.status(403).json({ error: "Access denied" });
    }
    next();
  };
}

app.get("/", (req, res) => {
  res.send("Server is running!");
});

app.get("/health", async (req, res) => {
  const result = await pool.query("SELECT NOW()");
  res.json({ status: "ok", dbTime: result.rows[0].now });
});

const PORT = 3000;
const bcrypt = require("bcrypt");

app.post("/register", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: "Email and password are required" });
    }

    const passwordHash = await bcrypt.hash(password, 10);

    const result = await pool.query(
      "INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING id, email",
      [email, passwordHash],
    );

    res.status(201).json({ message: "User created", user: result.rows[0] });
  } catch (err) {
    if (err.code === "23505") {
      return res.status(409).json({ error: "Email already registered" });
    }
    res.status(500).json({ error: "Something went wrong" });
  }
});

app.post("/register-v2", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: "Email and password are required" });
    }

    const passwordHash = await bcrypt.hash(password, 10);

    const user = await prisma.users.create({
      data: {
        email: email,
        password_hash: passwordHash,
      },
    });

    res.status(201).json({
      message: "User created",
      user: { id: user.id, email: user.email },
    });
  } catch (err) {
    if (err.code === "P2002") {
      return res.status(409).json({ error: "Email already registered" });
    }
    console.error(err); // ADD THIS LINE TEMPORARILY
    res.status(500).json({ error: "Something went wrong" });
  }
});

const jwt = require("jsonwebtoken");

app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: "Email and password are required" });
    }

    const result = await pool.query("SELECT * FROM users WHERE email = $1", [
      email,
    ]);
    const user = result.rows[0];

    if (!user) {
      return res.status(401).json({ error: "Invalid email or password" });
    }

    const isMatch = await bcrypt.compare(password, user.password_hash);

    if (!isMatch) {
      return res.status(401).json({ error: "Invalid email or password" });
    }

    const token = jwt.sign(
      { userId: user.id, email: user.email, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: "1h" },
    );

    res.json({ message: "Login successful", token });
  } catch (err) {
    res.status(500).json({ error: "Something went wrong" });
  }
});

app.get("/profile", requireAuth, (req, res) => {
  res.json({ message: "This is protected data", user: req.user });
});

app.get("/admin", requireAuth, requireRole("admin"), (req, res) => {
  res.json({ message: "Welcome, admin!" });
});

app.post("/posts", requireAuth, async (req, res) => {
  try {
    const { title, content } = req.body;
    const result = await pool.query(
      "INSERT INTO posts (title, content, user_id) VALUES ($1, $2, $3) RETURNING *",
      [title, content, req.user.userId],
    );
    res.status(201).json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ error: "Something went wrong" });
  }
});

app.put("/posts/:id", requireAuth, async (req, res) => {
  try {
    const postId = req.params.id;
    const { title, content } = req.body;

    const postResult = await pool.query("SELECT * FROM posts WHERE id = $1", [
      postId,
    ]);
    const post = postResult.rows[0];

    if (!post) {
      return res.status(404).json({ error: "Post not found" });
    }

    const isOwner = post.user_id === req.user.userId;
    const isAdmin = req.user.role === "admin";

    if (!isOwner && !isAdmin) {
      return res
        .status(403)
        .json({ error: "You can only edit your own posts" });
    }

    const updated = await pool.query(
      "UPDATE posts SET title = $1, content = $2 WHERE id = $3 RETURNING *",
      [title, content, postId],
    );

    res.json(updated.rows[0]);
  } catch (err) {
    res.status(500).json({ error: "Something went wrong" });
  }
});

app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
});
