import jwt from "jsonwebtoken";
import dotenv from "dotenv";

dotenv.config();

function generateToken(user, expiresIn = "24h") {
  return jwt.sign(
    { userId: user.id, email: user.email, role: user.role },
    process.env.JWT_SECRET,
    { expiresIn }
  );
}

function wait(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function main() {
  const sampleUser = { id: 1, email: "wanjiku@mail.com", role: "user" };

  // --- Test 1: Valid token ---------------------------------------------
  console.log("--- Test 1: Valid Token ---");
  const validToken = generateToken(sampleUser);
  console.log(`Token: ${validToken}`);
  const decoded = jwt.verify(validToken, process.env.JWT_SECRET);
  console.log("Decoded:", decoded);

  // --- Test 2: Expired token --------------------------------------------
  console.log("\n--- Test 2: Expired Token ---");
  const expiredToken = generateToken(sampleUser, "1s");
  await wait(2000); // let it expire
  try {
    jwt.verify(expiredToken, process.env.JWT_SECRET);
  } catch (err) {
    console.log(`Error: ${err.name} - ${err.message}`);
  }

  // --- Test 3: Tampered token --------------------------------------------
  console.log("\n--- Test 3: Tampered Token ---");
  const tokenToTamper = generateToken(sampleUser);
  // Flip one character near the end of the signature portion
  const tampered =
    tokenToTamper.slice(0, -1) +
    (tokenToTamper.slice(-1) === "a" ? "b" : "a");
  try {
    jwt.verify(tampered, process.env.JWT_SECRET);
  } catch (err) {
    console.log(`Error: ${err.name} - ${err.message}`);
  }
}

main();
