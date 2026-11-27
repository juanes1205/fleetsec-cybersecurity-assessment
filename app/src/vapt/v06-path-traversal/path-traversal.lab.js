const fs = require("node:fs");
const path = require("node:path");

/**
 * V-06 - Path Traversal (CWE-22)
 *
 * Laboratorio aislado para demostrar una lectura fuera del directorio
 * permitido utilizando únicamente archivos ficticios de prueba.
 */

/**
 * VERSIÓN VULNERABLE:
 * No valida que la ruta solicitada permanezca dentro de baseDir.
 */
function vulnerableReadFile(baseDir, file) {
  if (typeof file !== "string" || file.length === 0) {
    throw new TypeError("El nombre del archivo no es válido");
  }

  const targetPath = path.resolve(baseDir, file);

  return fs.readFileSync(targetPath, "utf8");
}

/**
 * VERSIÓN SEGURA:
 * Valida la ruta canónica y evita escapes del directorio permitido,
 * incluidos los accesos mediante enlaces simbólicos.
 */
function secureReadFile(baseDir, file) {
  if (
    typeof file !== "string" ||
    file.length === 0 ||
    file.includes("\0") ||
    path.isAbsolute(file)
  ) {
    throw new TypeError("El nombre del archivo no es válido");
  }

  const canonicalBase = fs.realpathSync(baseDir);
  const targetPath = path.resolve(canonicalBase, file);

  let canonicalTarget;

  try {
    canonicalTarget = fs.realpathSync(targetPath);
  } catch {
    throw new Error("Archivo no encontrado o ruta no permitida");
  }

  const relativePath = path.relative(canonicalBase, canonicalTarget);

  if (
    relativePath === ".." ||
    relativePath.startsWith(`..${path.sep}`) ||
    path.isAbsolute(relativePath)
  ) {
    throw new Error("Acceso denegado: ruta fuera del directorio permitido");
  }

  return fs.readFileSync(canonicalTarget, "utf8");
}

module.exports = {
  vulnerableReadFile,
  secureReadFile,
};
