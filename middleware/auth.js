import jwt from "jsonwebtoken";

// Shared with server.js so logout can blacklist tokens and this
// middleware can reject them. A Set of raw token strings.
export const tokenBlacklist = new Set();

export function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res
      .status(401)
      .json({ error: "Access denied. No token provided." });
  }

  const token = authHeader.slice("Bearer ".length).trim();

  if (tokenBlacklist.has(token)) {
    return res.status(401).json({ error: "Token has been revoked." });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      if (err.name === "TokenExpiredError") {
        return res
          .status(401)
          .json({ error: "Token has expired. Please log in again." });
      }
      return res.status(401).json({ error: "Invalid token." });
    }

    req.user = decoded;
    req.token = token; // handy for the logout route
    next();
  });
}
