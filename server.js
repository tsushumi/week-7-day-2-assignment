import express from "express";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
import { authenticateToken, tokenBlacklist } from "./middleware/auth.js";

dotenv.config();

const app = express();
app.use(express.json());

const SALT_ROUNDS = 10;
const PORT = process.env.PORT || 3000;

const ACCESS_TOKEN_TTL = "15m";
const REFRESH_TOKEN_TTL = "7d";

// ---------------------------------------------------------------------------
// In-memory "database"
// ---------------------------------------------------------------------------
const users = [];
let nextUserId = 1;

// Key: refresh token string -> userId (so we can verify it's still "live")
const refreshTokens = new Map();

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
function isValidEmail(email) {
  return typeof email === "string" && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function validatePassword(password) {
  if (typeof password !== "string" || password.length < 8) return false;
  if (!/[A-Z]/.test(password)) return false;
  if (!/[0-9]/.test(password)) return false;
  return true;
}

function findUserByEmail(email) {
  const lower = email.toLowerCase();
  return users.find((u) => u.email.toLowerCase() === lower);
}

function publicUser(user) {
  const { passwordHash, ...safe } = user;
  return safe;
}

// Task 1's generateToken, used for the classic single-token flows (register/login response `token`)
function generateToken(user, expiresIn = "24h") {
  return jwt.sign(
    { userId: user.id, email: user.email, role: user.role },
    process.env.JWT_SECRET,
    { expiresIn }
  );
}

function generateAccessToken(user) {
  return generateToken(user, ACCESS_TOKEN_TTL);
}

function generateRefreshToken(user) {
  const token = generateToken(user, REFRESH_TOKEN_TTL);
  refreshTokens.set(token, user.id);
  return token;
}

// ---------------------------------------------------------------------------
// Task 1 bonus route: GET /api/test-token — same 3 tests as token-demo.js,
// exposed as an endpoint too, per the "test script OR route" requirement.
// ---------------------------------------------------------------------------
app.get("/api/test-token", async (req, res) => {
  const sampleUser = { id: 1, email: "wanjiku@mail.com", role: "user" };
  const results = {};

  // Test 1: valid token
  const validToken = generateToken(sampleUser);
  results.test1_validToken = {
    token: validToken,
    decoded: jwt.verify(validToken, process.env.JWT_SECRET),
  };

  // Test 2: expired token
  const expiredToken = generateToken(sampleUser, "1s");
  await new Promise((resolve) => setTimeout(resolve, 2000));
  try {
    jwt.verify(expiredToken, process.env.JWT_SECRET);
    results.test2_expiredToken = { error: null };
  } catch (err) {
    results.test2_expiredToken = { error: `${err.name} - ${err.message}` };
  }

  // Test 3: tampered token
  const tokenToTamper = generateToken(sampleUser);
  const tampered =
    tokenToTamper.slice(0, -1) +
    (tokenToTamper.slice(-1) === "a" ? "b" : "a");
  try {
    jwt.verify(tampered, process.env.JWT_SECRET);
    results.test3_tamperedToken = { error: null };
  } catch (err) {
    results.test3_tamperedToken = { error: `${err.name} - ${err.message}` };
  }

  res.json(results);
});

// ---------------------------------------------------------------------------
// Task 3: POST /api/auth/register
// ---------------------------------------------------------------------------
app.post("/api/auth/register", async (req, res) => {
  const { email, password, name } = req.body || {};

  if (!isValidEmail(email)) {
    return res.status(400).json({ error: "A valid email is required" });
  }
  if (!validatePassword(password)) {
    return res.status(400).json({
      error:
        "Password must be at least 8 characters, contain one uppercase letter and one number",
    });
  }
  if (typeof name !== "string" || name.trim().length < 2) {
    return res.status(400).json({ error: "Name must be at least 2 characters" });
  }
  if (findUserByEmail(email)) {
    return res.status(409).json({ error: "Email already registered" });
  }

  const passwordHash = await bcrypt.hash(password, SALT_ROUNDS);
  const user = { id: nextUserId++, email, name: name.trim(), role: "user", passwordHash };
  users.push(user);

  const token = generateToken(user);

  return res.status(201).json({ token, user: publicUser(user) });
});

// ---------------------------------------------------------------------------
// Task 3: POST /api/auth/login
// (issues both the classic `token` field AND accessToken/refreshToken,
//  so it works for both the plain Task 3 flow and the bonus refresh flow)
// ---------------------------------------------------------------------------
app.post("/api/auth/login", async (req, res) => {
  const { email, password } = req.body || {};

  if (typeof email !== "string" || typeof password !== "string") {
    return res.status(400).json({ error: "Email and password are required" });
  }

  const user = findUserByEmail(email);
  const passwordMatches = user
    ? await bcrypt.compare(password, user.passwordHash)
    : false;

  if (!user || !passwordMatches) {
    return res.status(401).json({ error: "Invalid email or password" });
  }

  const token = generateToken(user); // 24h, for simple Task 3 usage
  const accessToken = generateAccessToken(user); // 15m, bonus
  const refreshToken = generateRefreshToken(user); // 7d, bonus

  return res.status(200).json({
    token,
    accessToken,
    refreshToken,
    user: publicUser(user),
  });
});

// ---------------------------------------------------------------------------
// Task 3: GET /api/profile — protected
// ---------------------------------------------------------------------------
app.get("/api/profile", authenticateToken, (req, res) => {
  const user = users.find((u) => u.id === req.user.userId);

  if (!user) {
    return res.status(404).json({ error: "User not found" });
  }

  return res.status(200).json({ user: publicUser(user) });
});

// ---------------------------------------------------------------------------
// Bonus: POST /api/auth/refresh
// ---------------------------------------------------------------------------
app.post("/api/auth/refresh", (req, res) => {
  const { refreshToken } = req.body || {};

  if (typeof refreshToken !== "string" || !refreshTokens.has(refreshToken)) {
    return res.status(401).json({ error: "Invalid refresh token." });
  }

  jwt.verify(refreshToken, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      refreshTokens.delete(refreshToken);
      if (err.name === "TokenExpiredError") {
        return res
          .status(401)
          .json({ error: "Refresh token has expired. Please log in again." });
      }
      return res.status(401).json({ error: "Invalid refresh token." });
    }

    const user = users.find((u) => u.id === decoded.userId);
    if (!user) {
      return res.status(401).json({ error: "Invalid refresh token." });
    }

    const accessToken = generateAccessToken(user);
    return res.status(200).json({ accessToken });
  });
});

// ---------------------------------------------------------------------------
// Bonus: POST /api/auth/logout
// ---------------------------------------------------------------------------
app.post("/api/auth/logout", authenticateToken, (req, res) => {
  tokenBlacklist.add(req.token);
  return res.status(200).json({ message: "Logged out successfully" });
});

app.listen(PORT, () => {
  console.log(`Server listening on http://localhost:${PORT}`);
});
