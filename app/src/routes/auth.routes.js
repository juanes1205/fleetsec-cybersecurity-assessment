const express = require("express");

const {
  login,
  getCurrentUser,
} = require("../controllers/auth.controller");

const {
  authenticateToken,
} = require("../middleware/auth.middleware");

const loginRateLimiter = require("../middleware/login-rate-limit.middleware");

const router = express.Router();

// Inicio de sesión protegido contra intentos excesivos.
router.post("/login", loginRateLimiter, login);

// Información del usuario autenticado.
router.get("/me", authenticateToken, getCurrentUser);

module.exports = router;
