const app = require("./app");
const { initializeDatabase, db } = require("./database");
const { seedDatabase } = require("./config/seed");

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
      console.log(`FleetSec API running on port ${PORT}`);
    });

    // Cierre controlado.
    const shutdown = (signal) => {
      console.log(`${signal} received. Shutting down...`);

      server.close(() => {
        db.close();
        console.log("Database connection closed");
        process.exit(0);
      });
    };

    process.once("SIGINT", () => shutdown("SIGINT"));
    process.once("SIGTERM", () => shutdown("SIGTERM"));

    return server;
  } catch (error) {
    console.error("Application startup failed:", error.message);
    db.close();
    process.exitCode = 1;
  }
}

if (require.main === module) {
  startServer();
}

module.exports = { app, startServer };
