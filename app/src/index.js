const app = require("./app");
const { initializeDatabase, db } = require("./database");
const { seedDatabase } = require("./config/seed");
const logger = require("./utils/secure-logger");

const PORT = process.env.PORT || 3000;

function startServer() {
  try {
    // Crear las tablas.
    initializeDatabase();

    // Cargar datos iniciales cuando esté habilitado.
    if (process.env.SEED_ON_STARTUP === "true") {
      seedDatabase();
    }

    const server = app.listen(PORT, () => {
      logger.info("FleetSec API started", {
        port: PORT,
      });
    });

    // Cierre controlado.
    const shutdown = (signal) => {
      logger.info("Shutdown signal received", {
        signal,
      });

      server.close(() => {
        db.close();
        logger.info("Database connection closed");
        process.exit(0);
      });
    };

    process.once("SIGINT", () => shutdown("SIGINT"));
    process.once("SIGTERM", () => shutdown("SIGTERM"));

    return server;
  } catch (error) {
    logger.error("Application startup failed", {
      error,
    });
    db.close();
    process.exitCode = 1;
  }
}

if (require.main === module) {
  startServer();
}

module.exports = { app, startServer };
