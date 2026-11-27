const express = require("express");
const logger = require("../../utils/secure-logger");

function createLoggingLab() {
  const app = express();

  app.use(express.json({ limit: "10kb" }));

  // Escenario vulnerable: registra directamente el cuerpo recibido.
  app.post("/vulnerable-log", (req, res) => {
    console.log("Authentication event:", req.body);

    return res.status(200).json({
      message: "Vulnerable log generated",
    });
  });

  // Escenario seguro: registra los datos mediante el logger sanitizado.
  app.post("/secure-log", (req, res) => {
    logger.info("Authentication event", req.body);

    return res.status(200).json({
      message: "Secure log generated",
    });
  });

  return app;
}

module.exports = {
  createLoggingLab,
};
