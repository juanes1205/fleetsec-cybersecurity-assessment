const express = require("express");

const { getOwnedDocument } = require("../controllers/document.controller");
const { authenticateToken } = require("../middleware/auth.middleware");

const router = express.Router();

// Consultar un documento propio.
router.get("/:id", authenticateToken, getOwnedDocument);

module.exports = router;
