const express = require("express");

const { authenticateToken } = require("../../middleware/auth.middleware");

/**
 * V-09 - IDOR (CWE-639)
 * Laboratorio controlado con SQLite y usuarios ficticios.
 */

function isValidIdentifier(value) {
  const identifier = Number(value);

  return Number.isSafeInteger(identifier) && identifier > 0;
}

/**
 * Consulta vulnerable:
 * no verifica que el usuario autenticado sea propietario del activo.
 */
function getDocumentVulnerable(database, documentId) {
  if (!isValidIdentifier(documentId)) {
    return null;
  }

  return (
    database
      .prepare(
        `
        SELECT
          d.id,
          d.asset_id,
          d.filename,
          d.storage_path,
          a.owner_user_id
        FROM documents d
        INNER JOIN assets a ON a.id = d.asset_id
        WHERE d.id = ?
      `,
      )
      .get(Number(documentId)) || null
  );
}

/**
 * Consulta segura:
 * exige que el activo pertenezca al usuario autenticado.
 */
function getDocumentSecure(database, documentId, userId) {
  if (!isValidIdentifier(documentId) || !isValidIdentifier(userId)) {
    return null;
  }

  return (
    database
      .prepare(
        `
        SELECT
          d.id,
          d.asset_id,
          d.filename,
          d.storage_path,
          a.owner_user_id
        FROM documents d
        INNER JOIN assets a ON a.id = d.asset_id
        WHERE d.id = ?
          AND a.owner_user_id = ?
      `,
      )
      .get(Number(documentId), Number(userId)) || null
  );
}

function createIdorLab(database) {
  const router = express.Router();

  // Endpoint vulnerable: cualquier usuario autenticado
  // puede consultar el documento si conoce su identificador.
  router.get("/vulnerable/documents/:id", authenticateToken, (req, res) => {
    const document = getDocumentVulnerable(database, req.params.id);

    if (!document) {
      return res.status(404).json({
        error: "Document not found",
      });
    }

    return res.status(200).json({ document });
  });

  // Endpoint protegido: verifica la propiedad del activo.
  router.get("/secure/documents/:id", authenticateToken, (req, res) => {
    const document = getDocumentSecure(database, req.params.id, req.user.id);

    if (!document) {
      return res.status(404).json({
        error: "Document not found",
      });
    }

    return res.status(200).json({ document });
  });

  return router;
}

module.exports = {
  getDocumentVulnerable,
  getDocumentSecure,
  createIdorLab,
};
