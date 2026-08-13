// Loads variables from your .env file into process.env
// (DATABASE_URL, JWT_SECRET, GEMINI_API_KEY, etc.)
require("dotenv").config();

// Zod = schema validation library. Used to check that incoming
// request bodies (email, password, etc.) are shaped correctly
// BEFORE you touch the database.
const { z } = require("zod");

// Google's Gemini SDK — lets you call Gemini models from your backend.
const { GoogleGenAI } = require("@google/genai");
const ai = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY });

// Quick sanity check on startup: confirms your .env values are
// actually being loaded (remove this once you trust your setup —
// logging DB URLs is a habit to drop before deploying anywhere real).
console.log("DB URL loaded:", process.env.DATABASE_URL);

// Prisma = your ORM (Object-Relational Mapper). Instead of writing
// raw SQL everywhere, you call methods like prisma.users.create(...)
// and Prisma translates that into SQL for you.
const { PrismaClient } = require("./generated/prisma");

// The "adapter" tells Prisma to use the `pg` (node-postgres) driver
// under the hood instead of its own default connection engine.
const { PrismaPg } = require("@prisma/adapter-pg");

const adapter = new PrismaPg({ connectionString: process.env.DATABASE_URL });
const prisma = new PrismaClient({ adapter });

const express = require("express");
const { Pool } = require("pg"); // raw Postgres client (used alongside Prisma in some routes)

const app = express();
app.use(express.json()); // lets Express parse incoming JSON request bodies into req.body

// --- VALIDATION SCHEMA ---
// Defines the "shape" a registration request must have.
// If email isn't a valid email, or password is under 6 chars,
// parsing will fail and you can reject the request early.
const registerSchema = z.object({
  email: z.string().email("Invalid email format"),
  password: z.string().min(6, "Password must be at least 6 characters"),
});

// Raw Postgres connection pool — used by your "v1" routes
// (the ones written with plain SQL queries instead of Prisma).
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

// --- AUTH MIDDLEWARE ---
// Runs before any route that needs a logged-in user.
// Checks for a "Bearer <token>" header, verifies the JWT,
// and attaches the decoded payload to req.user so later
// route handlers can access req.user.userId, req.user.role, etc.
function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer")) {
    return res.status(401).json({ error: "No token provided" });
  }

  const token = authHeader.split(" ")[1]; // "Bearer <token>" -> just <token>

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded; // now available in any route after this middleware
    next(); // move on to the actual route handler
  } catch (err) {
    // covers both invalid signature AND expired tokens
    return res.status(401).json({ error: "Invalid or expired token" });
  }
}

// --- ROLE-BASED ACCESS CONTROL (RBAC) ---
// A middleware FACTORY: requireRole("admin") returns a middleware
// function that checks req.user.role (set by requireAuth above)
// matches the required role. Must run AFTER requireAuth.
function requireRole(role) {
  return (req, res, next) => {
    if (req.user.role !== role) {
      return res.status(403).json({ error: "Access denied" });
    }
    next();
  };
}

// --- BASIC ROUTES ---

// Simple "is the server alive" check
app.get("/", (req, res) => {
  res.send("Server is running!");
});

// Confirms the DB connection actually works by asking Postgres
// for the current time — a common health-check pattern.
app.get("/health", async (req, res) => {
  const result = await pool.query("SELECT NOW()");
  res.json({ status: "ok", dbTime: result.rows[0].now });
});

const PORT = 3000;
const bcrypt = require("bcrypt"); // for hashing passwords (never store plain text passwords!)
const jwt = require("jsonwebtoken"); // for creating/verifying login tokens

// --- Simple Test Route ---
app.post("/chat", requireAuth, async (req, res) => {
  try {
    const { message, history } = req.body;

    if (!message) {
      return res.status(400).json({
        error: "Message is Required",
      });
    }

    const conversation = history || [];

    const response = await ai.models.generateContent({
      model: "gemini-3.1-flash-lite",
      contents: [
        ...conversation,
        {
          role: "user",
          parts: [
            {
              text: message,
            },
          ],
        },
      ],
      config: {
        systemInstruction:
          "You are a friendly assistant for a task management app. Keep answers short and practical. If asked something unrelated to tasks or productivity, politely redirect the user back to the app's purpose.",
      },
    });

    res.json({ reply: response.text });
  } catch (err) {
    console.error(err);

    if (err.status === 429) {
      return res.status(429).json({
        error: "AI service is temporarily busy. Please try again in a moment.",
      });
    }

    if (err.status === 400) {
      return res
        .status(400)
        .json({ error: "That request couldn't be processed." });
    }

    res
      .status(500)
      .json({ error: "Something went wrong with the AI request." });
  }
});

// --- REGISTER (v1: raw SQL, minimal validation) ---
app.post("/register", async (req, res) => {
  try {
    const { email, password } = req.body;

    // manual validation — just checks the fields exist, not that they're well-formed
    if (!email || !password) {
      return res.status(400).json({ error: "Email and password are required" });
    }

    // NEVER store raw passwords — bcrypt.hash() turns it into a
    // one-way hash. "10" is the salt rounds (cost factor);
    // higher = slower to compute = more resistant to brute force.
    const passwordHash = await bcrypt.hash(password, 10);

    const result = await pool.query(
      "INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING id, email",
      [email, passwordHash], // parameterized query — prevents SQL injection
    );

    res.status(201).json({ message: "User created", user: result.rows[0] });
  } catch (err) {
    // Postgres error code 23505 = unique constraint violation
    // (i.e. this email is already registered)
    if (err.code === "23505") {
      return res.status(409).json({ error: "Email already registered" });
    }
    res.status(500).json({ error: "Something went wrong" });
  }
});

// --- REGISTER (v2: Prisma + Zod validation — the "better" version) ---
app.post("/register-v2", async (req, res) => {
  try {
    // safeParse won't throw — it returns { success, data } or { success, error }
    // so you can handle bad input gracefully instead of try/catching a thrown error
    const parsed = registerSchema.safeParse(req.body);

    if (!parsed.success) {
      return res.status(400).json({ error: parsed.error.issues[0].message });
    }

    const { email, password } = parsed.data; // validated + typed data

    const passwordHash = await bcrypt.hash(password, 10);

    // Prisma equivalent of the raw INSERT above
    const user = await prisma.users.create({
      data: {
        email: email,
        password_hash: passwordHash,
      },
    });

    res.status(201).json({
      message: "User created",
      user: { id: user.id, email: user.email }, // never send password_hash back!
    });
  } catch (err) {
    // Prisma's version of "duplicate key" is error code P2002
    if (err.code === "P2002") {
      return res.status(409).json({ error: "Email already registered" });
    }
    console.error(err); // TEMP: helps you debug — remove or replace with real logging later
    res.status(500).json({ error: "Something went wrong" });
  }
});

// --- LOGIN (v1: raw SQL) ---
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
      // deliberately vague — don't reveal whether it was the
      // email or the password that was wrong (avoids leaking
      // which emails are registered)
      return res.status(401).json({ error: "Invalid email or password" });
    }

    // bcrypt.compare hashes the input password with the same salt
    // and checks it against the stored hash
    const isMatch = await bcrypt.compare(password, user.password_hash);

    if (!isMatch) {
      return res.status(401).json({ error: "Invalid email or password" });
    }

    // Create a signed JWT containing user info ("claims").
    // Anyone with JWT_SECRET can verify this token wasn't tampered with.
    const token = jwt.sign(
      { userId: user.id, email: user.email, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }, // token becomes invalid after 1 hour
    );

    res.json({ message: "Login successful", token });
  } catch (err) {
    res.status(500).json({ error: "Something went wrong" });
  }
});

// --- LOGIN (v2: Prisma) ---
app.post("/login-v2", async (req, res) => {
  try {
    const { email, password } = req.body;

    // NOTE: this schema is defined again here but never actually used
    // in this route (login doesn't call .parse/.safeParse on it) —
    // likely leftover/dead code from copy-pasting register-v2.
    const { z } = require("zod");
    const registerSchema = z.object({
      email: z.string().email("Invalid email format"),
      password: z.string().min(6, "Password must be at least 6 characters"),
    });

    const user = await prisma.users.findUnique({
      where: {
        email: email,
      },
    });

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
  } catch (error) {
    res.status(500).json({ error: "Something went wrong" });
  }
});

// --- PROTECTED ROUTES ---

// requireAuth runs first — if the token is valid, req.user is available here
app.get("/profile", requireAuth, (req, res) => {
  res.json({ message: "This is protected data", user: req.user });
});

// requireAuth AND requireRole("admin") both run before this handler —
// order matters: you must know WHO the user is before checking WHAT they can do
app.get("/admin", requireAuth, requireRole("admin"), (req, res) => {
  res.json({ message: "Welcome, admin!" });
});

// --- POSTS (v1: raw SQL) ---
app.post("/posts", requireAuth, async (req, res) => {
  try {
    const { title, content } = req.body;
    const result = await pool.query(
      "INSERT INTO posts (title, content, user_id) VALUES ($1, $2, $3) RETURNING *",
      [title, content, req.user.userId], // user_id comes from the verified token, not the request body — this prevents users from creating posts "as" someone else
    );
    res.status(201).json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ error: "Something went wrong" });
  }
});

// --- POSTS (v2: Prisma) ---
app.post("/posts-v2", requireAuth, async (req, res) => {
  try {
    const { title, content } = req.body;

    const post = await prisma.posts.create({
      data: {
        title: title,
        content: content,
        user_id: req.user.userId,
      },
    });

    res.status(201).json({
      message: "Post Created",
      post: {
        title: title,
        content: content,
        // NOTE: this doesn't return post.id — might be worth adding
        // if the frontend needs the new post's ID right after creation
      },
    });
  } catch (error) {
    res.status(500).json({ error: "Something went wrong" });
  }
});

// --- UPDATE POST (ownership + admin override check) ---
app.put("/posts/:id", requireAuth, async (req, res) => {
  try {
    const postId = req.params.id; // from the URL, e.g. /posts/42 -> "42"
    const { title, content } = req.body;

    const postResult = await pool.query("SELECT * FROM posts WHERE id = $1", [
      postId,
    ]);
    const post = postResult.rows[0];

    if (!post) {
      return res.status(404).json({ error: "Post not found" });
    }

    // ownership/authorization check: does this post belong to the
    // logged-in user, OR are they an admin who can override that?
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

// Starts the server listening on PORT (3000)
app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
});
