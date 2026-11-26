const express = require("express");

const { login, getCurrentUser } = require("../controllers/auth.controller");

const { authenticateToken } = require("../middleware/auth.middleware");

const router = express.Router();

// Inicio de sesión.
router.post("/login", login);

// Información del usuario autenticado.
router.get("/me", authenticateToken, getCurrentUser);

module.exports = router;
