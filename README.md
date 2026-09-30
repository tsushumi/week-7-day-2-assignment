# Week 7, Day 2 — JWT Authentication, Middleware & Protected Routes

An Express API that layers JWT-based auth on top of Day 1's bcrypt work:
signing/verifying tokens, an `authenticateToken` middleware, full
register/login/profile endpoints, and a bonus access/refresh-token +
logout-blacklist flow.

## Setup

```bash
git clone <this-repo-url>
npm install
```

`package.json` has `"type": "module"`, so the code uses ES module `import` syntax.

### Task 1 — JWT generate/verify demo

```bash
node token-demo.js
```

### Tasks 2, 3 & Bonus — the API server

```bash
node server.js
# Server listening on http://localhost:3000
```

Users, and refresh/blacklisted tokens all live in memory and reset on restart.

---

## Task 1: `token-demo.js` — sample output

```text
--- Test 1: Valid Token ---
Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOjEsImVtYWlsIjoid2FuamlrdUBtYWlsLmNvbSIsInJvbGUiOiJ1c2VyIiwiaWF0IjoxNzkwNzU0NjY4LCJleHAiOjE3OTA4NDEwNjh9.02pgwlAMXhf_MFr-8LT6JgI4Qa17NkhqFWNqoa2cOA8
Decoded: {
  userId: 1,
  email: 'wanjiku@mail.com',
  role: 'user',
  iat: 1790754668,
  exp: 1790841068
}

--- Test 2: Expired Token ---
Error: TokenExpiredError - jwt expired

--- Test 3: Tampered Token ---
Error: JsonWebTokenError - invalid signature
```

`generateToken(user)` signs `{ userId, email, role }` with `process.env.JWT_SECRET`
(never hardcoded) and a 24-hour expiry, exactly as specified. The expired-token
test uses a real `expiresIn: '1s'` token and waits 2 seconds before verifying;
the tampered-token test flips the last character of a valid token before
verifying it.

The same three checks are also exposed as `GET /api/test-token` on the running
server, in case you'd rather hit it with curl than run the script:

```bash
curl http://localhost:3000/api/test-token
```
```json
{
  "test1_validToken": { "token": "eyJ...", "decoded": { "userId": 1, "email": "wanjiku@mail.com", "role": "user", "iat": 1790754705, "exp": 1790841105 } },
  "test2_expiredToken": { "error": "TokenExpiredError - jwt expired" },
  "test3_tamperedToken": { "error": "JsonWebTokenError - invalid signature" }
}
```
(This route takes ~2 seconds to respond because it deliberately waits for
the Test 2 token to expire before verifying it.)

---

## Task 2: `authenticateToken` middleware (`middleware/auth.js`)

```bash
# No token
curl -i http://localhost:3000/api/profile
```
```text
401
{"error":"Access denied. No token provided."}
```

```bash
# Invalid token
curl -i http://localhost:3000/api/profile \
  -H "Authorization: Bearer this-is-not-a-real-token"
```
```text
401
{"error":"Invalid token."}
```

```bash
# Valid token (from login, see Task 3 below)
curl -i http://localhost:3000/api/profile \
  -H "Authorization: Bearer YOUR_VALID_TOKEN"
```
```text
200
{"user":{"id":1,"email":"wanjiku@mail.com","name":"Wanjiku","role":"user"}}
```

The middleware also distinguishes an **expired** token from a merely invalid
one (`"Token has expired. Please log in again."` vs `"Invalid token."`), and
checks a blacklist before verifying (see the bonus logout flow below).

---

## Task 3: register → login → profile

```bash
# 1. Register
curl -X POST http://localhost:3000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email": "wanjiku@mail.com", "password": "Secure123", "name": "Wanjiku"}'
```
```json
201
{"token":"eyJ...","user":{"id":1,"email":"wanjiku@mail.com","name":"Wanjiku","role":"user"}}
```

```bash
# 2. Login
curl -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "wanjiku@mail.com", "password": "Secure123"}'
```
```json
200
{"token":"eyJ...","accessToken":"eyJ...","refreshToken":"eyJ...","user":{"id":1,"email":"wanjiku@mail.com","name":"Wanjiku","role":"user"}}
```
(`token` is a plain 24h token, per the Task 3 spec. `accessToken`/`refreshToken`
are the bonus short-lived/long-lived pair — see below. Use whichever your
client needs; both are valid for `/api/profile`.)

```bash
# 3. Access profile with the token from login
curl -X POST http://localhost:3000/api/profile \
  -H "Authorization: Bearer YOUR_TOKEN_FROM_LOGIN"
```
```json
200
{"user":{"id":1,"email":"wanjiku@mail.com","name":"Wanjiku","role":"user"}}
```

```bash
# 4. Access profile without a token
curl http://localhost:3000/api/profile
```
```json
401
{"error":"Access denied. No token provided."}
```

Passwords are hashed with bcrypt (cost `10`) before storage; `passwordHash`
is never included in a response. `/api/profile` reads `req.user.userId`
(set by the middleware from the decoded token) to look up the current user.

---

## Bonus: access/refresh tokens + logout blacklist

Login (above) already returns both `accessToken` (15 min) and `refreshToken`
(7 days).

```bash
# Get a new access token once the old one is close to expiring
curl -X POST http://localhost:3000/api/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{"refreshToken": "YOUR_REFRESH_TOKEN"}'
```
```json
200
{"accessToken":"eyJ..."}
```

An unknown or expired refresh token returns `401` with
`{"error": "Invalid refresh token."}` or
`{"error": "Refresh token has expired. Please log in again."}`.

```bash
# Log out: blacklist the token you're currently using
curl -X POST http://localhost:3000/api/auth/logout \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```
```json
200
{"message":"Logged out successfully"}
```

```bash
# Reuse the same (now blacklisted) token
curl http://localhost:3000/api/profile \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```
```json
401
{"error":"Token has been revoked."}
```

The blacklist is an in-memory `Set` of raw token strings (`tokenBlacklist`,
exported from `middleware/auth.js`), checked by `authenticateToken` before
the token is even verified.

---
