const { db } = require("../database");

/**
 * Consulta un documento únicamente si pertenece al usuario autenticado.
 */
function getOwnedDocument(req, res, next) {
  const documentId = Number(req.params.id);

  if (!/^[1-9]\d*$/.test(req.params.id) || !Number.isSafeInteger(documentId)) {
    return res.status(404).json({
      error: "Document not found",
    });
  }

  try {
    const document = db
      .prepare(
        `
        SELECT
          d.id,
          d.asset_id,
          d.filename,
          d.created_at
        FROM documents d
        INNER JOIN assets a ON a.id = d.asset_id
        WHERE d.id = ?
          AND a.owner_user_id = ?
      `,
      )
      .get(documentId, req.user.id);

    if (!document) {
      return res.status(404).json({
        error: "Document not found",
      });
    }

    return res.status(200).json({ document });
  } catch (error) {
    return next(error);
  }
}

module.exports = {
  getOwnedDocument,
};
