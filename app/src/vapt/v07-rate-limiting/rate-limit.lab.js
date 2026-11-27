const express = require("express");
const { rateLimit } = require("express-rate-limit");

const LAB_CREDENTIALS = {
  email: "lab.user@fleetsec.local",
  password: "Lab_Password_2026!",
};

const RATE_LIMIT_WINDOW_MS = 60 * 1000;
const RATE_LIMIT_MAX_REQUESTS = 3;

/**
 * Endpoint de autenticación ficticio.
 * No consulta bases de datos ni utiliza credenciales reales.
 */
function loginHandler(req, res) {
  const { email, password } = req.body || {};

  if (
    email === LAB_CREDENTIALS.email &&
    password === LAB_CREDENTIALS.password
  ) {
    return res.status(200).json({
      message: "Authentication successful",
    });
  }

  return res.status(401).json({
    error: "Invalid credentials",
  });
}

/**
 * VERSIÓN VULNERABLE:
 * No aplica limitación de solicitudes al inicio de sesión.
 */
function createVulnerableApp() {
  const app = express();

  app.use(express.json());

  app.post("/api/auth/login", loginHandler);

  return app;
}

/**
 * VERSIÓN SEGURA:
 * Limita los intentos de autenticación por IP.
 */
function createSecureApp() {
  const app = express();

  app.use(express.json());

  const loginRateLimiter = rateLimit({
    windowMs: RATE_LIMIT_WINDOW_MS,
    limit: RATE_LIMIT_MAX_REQUESTS,
    standardHeaders: "draft-8",
    legacyHeaders: false,
    message: {
      error: "Too many login attempts. Please try again later.",
    },
  });

  app.post("/api/auth/login", loginRateLimiter, loginHandler);

  return app;
}

module.exports = {
  createVulnerableApp,
  createSecureApp,
  LAB_CREDENTIALS,
  RATE_LIMIT_MAX_REQUESTS,
  RATE_LIMIT_WINDOW_MS,
};
