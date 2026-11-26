const { DatabaseSync } = require("node:sqlite");
const fs = require("node:fs");
const path = require("node:path");

// Directorio donde se almacenará la base de datos.
const DATA_DIR = path.resolve(__dirname, "../../data");

if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

// Permite definir una ruta personalizada mediante DB_PATH.
const DB_PATH = process.env.DB_PATH
  ? path.resolve(process.cwd(), process.env.DB_PATH)
  : path.join(DATA_DIR, "fleetsec.db");

// Crear o abrir la base de datos.
const db = new DatabaseSync(DB_PATH);

// Configuración de SQLite.
db.exec(`
  PRAGMA foreign_keys = ON;
  PRAGMA journal_mode = WAL;
  PRAGMA busy_timeout = 5000;
`);

module.exports = db;
