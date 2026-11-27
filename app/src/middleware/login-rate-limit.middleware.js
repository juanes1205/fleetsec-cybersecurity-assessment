const { rateLimit } = require("express-rate-limit");

const windowMs = Number(
  process.env.LOGIN_RATE_LIMIT_WINDOW_MS || 15 * 60 * 1000,
);

const limit = Number(process.env.LOGIN_RATE_LIMIT_MAX || 5);

if (!Number.isInteger(windowMs) || windowMs <= 0) {
  throw new Error("LOGIN_RATE_LIMIT_WINDOW_MS must be a positive integer");
}

if (!Number.isInteger(limit) || limit <= 0) {
  throw new Error("LOGIN_RATE_LIMIT_MAX must be a positive integer");
}

/**
 * Limita los intentos de inicio de sesión por dirección IP.
 *
 * Configuración predeterminada:
 * - Ventana: 15 minutos.
 * - Máximo: 5 solicitudes.
 * - HTTP 429 al superar el límite.
 * - Encabezados estándar de Rate Limiting.
 */
const loginRateLimiter = rateLimit({
  windowMs,
  limit,
  standardHeaders: "draft-8",
  legacyHeaders: false,
  message: {
    error: "Too many login attempts. Please try again later.",
  },
});

module.exports = loginRateLimiter;
