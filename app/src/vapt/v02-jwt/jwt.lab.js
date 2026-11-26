const jwt = require("jsonwebtoken");

/**
 * V-02: implementación deliberadamente insegura.
 *
 * Decodificar un JWT NO verifica su firma.
 * Uso exclusivo en el laboratorio local.
 */
function unsafeDecodeToken(token) {
  return jwt.decode(token);
}

module.exports = {
  unsafeDecodeToken,
};
