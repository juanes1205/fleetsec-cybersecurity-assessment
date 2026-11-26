/**
 * Laboratorio V-01: SQL Injection (CWE-89).
 *
 * Solo debe utilizarse en pruebas locales con datos ficticios.
 * No debe conectarse a la API ni exponerse mediante HTTP.
 */

function vulnerableSearch(db, name) {
  // Implementación intencionalmente vulnerable.
  // Se utiliza exclusivamente para demostrar el defecto.
  const query = `
    SELECT id, name, description
    FROM assets
    WHERE name = '${name}'
  `;

  return db.prepare(query).all();
}

function secureSearch(db, name) {
  // Implementación corregida: consulta parametrizada.
  const query = `
    SELECT id, name, description
    FROM assets
    WHERE name = ?
  `;

  return db.prepare(query).all(name);
}

module.exports = {
  vulnerableSearch,
  secureSearch,
};
