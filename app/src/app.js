require("dotenv").config();

const express = require("express");
const helmet = require("helmet");
const cors = require("cors");
const morgan = require("morgan");

const {
  authenticateToken,
  authorizeRoles,
} = require("./middleware/auth.middleware");

const authRoutes = require("./routes/auth.routes");

const app = express();

// Configuración de seguridad HTTP.
app.use(helmet());

// Configuración de CORS mediante lista de orígenes permitidos.
const allowedOrigins = (process.env.CORS_ORIGINS || "http://localhost:5173")
  .split(",")
  .map((origin) => origin.trim())
  .filter(Boolean);

app.use(
  cors({
    origin(origin, callback) {
      // Permite solicitudes sin Origin, como pruebas y clientes backend.
      if (!origin || allowedOrigins.includes(origin)) {
        return callback(null, true);
      }

      return callback(new Error("Origin not allowed by CORS"));
    },
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE"],
    allowedHeaders: ["Content-Type", "Authorization"],
  }),
);

// Limitar tamaño del cuerpo de las solicitudes.
app.use(express.json({ limit: "10kb" }));

// Logs sin URL, query string, cuerpo ni dirección IP.
app.use(morgan(":method :status :response-time ms"));

// Ruta principal.
app.get("/", (req, res) => {
  res.status(200).json({
    message: "FleetSec Security API",
    version: "1.0.0",
  });
});

// Verificación de disponibilidad.
app.get("/health", (req, res) => {
  res.status(200).json({
    status: "OK",
    application: "FleetSec API",
    timestamp: new Date().toISOString(),
  });
});

app.use("/api/auth", authRoutes);

// Ruta exclusiva para administradores.
app.get(
  "/api/admin/dashboard",
  authenticateToken,
  authorizeRoles("admin"),
  (req, res) => {
    res.status(200).json({
      message: "Administrator access granted",
      user: {
        id: req.user.id,
        email: req.user.email,
        role: req.user.role,
      },
    });
  },
);

// Respuesta para rutas inexistentes.
app.use((req, res) => {
  res.status(404).json({
    error: "Route not found",
  });
});

// Manejador centralizado de errores.
app.use((err, req, res, next) => {
  if (res.headersSent) {
    return next(err);
  }

  if (err.type === "entity.parse.failed") {
    return res.status(400).json({
      error: "Invalid JSON payload",
    });
  }

  if (err.type === "entity.too.large") {
    return res.status(413).json({
      error: "Request body too large",
    });
  }

  if (err.message === "Origin not allowed by CORS") {
    return res.status(403).json({
      error: "Origin not allowed",
    });
  }

  console.error("Application error:", err.message);

  return res.status(500).json({
    error: "Internal server error",
  });
});

module.exports = app;
