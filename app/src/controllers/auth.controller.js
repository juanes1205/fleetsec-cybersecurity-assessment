const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const { db } = require("../database");

const {
  JWT_SECRET,
  JWT_ISSUER,
  JWT_AUDIENCE,
  JWT_EXPIRES_IN,
} = require("../config/auth");

async function login(req, res) {
  const { email, password } = req.body || {};

  // Validar los datos recibidos.
  if (
    typeof email !== "string" ||
    typeof password !== "string" ||
    email.length > 254 ||
    password.length > 128 ||
    !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim())
  ) {
    return res.status(400).json({
      error: "Invalid email or password format",
    });
  }

  const normalizedEmail = email.trim().toLowerCase();

  // Consulta parametrizada para evitar SQL Injection.
  const user = db
    .prepare(
      `
    SELECT id, name, email, password_hash, role
    FROM users
    WHERE email = ?
  `,
    )
    .get(normalizedEmail);

  // La respuesta no revela si el correo existe.
  const validPassword = user
    ? await bcrypt.compare(password, user.password_hash)
    : false;

  if (!user || !validPassword) {
    return res.status(401).json({
      error: "Invalid credentials",
    });
  }

  const accessToken = jwt.sign(
    {
      email: user.email,
      role: user.role,
    },
    JWT_SECRET,
    {
      algorithm: "HS256",
      subject: String(user.id),
      issuer: JWT_ISSUER,
      audience: JWT_AUDIENCE,
      expiresIn: JWT_EXPIRES_IN,
    },
  );

  return res.status(200).json({
    message: "Authentication successful",
    accessToken,
    tokenType: "Bearer",
    expiresIn: JWT_EXPIRES_IN,
    user: {
      id: user.id,
      name: user.name,
      email: user.email,
      role: user.role,
    },
  });
}

function getCurrentUser(req, res) {
  const user = db
    .prepare(
      `
    SELECT id, name, email, role, created_at
    FROM users
    WHERE id = ?
  `,
    )
    .get(req.user.id);

  if (!user) {
    return res.status(401).json({
      error: "User no longer exists",
    });
  }

  return res.status(200).json({ user });
}

module.exports = {
  login,
  getCurrentUser,
};
