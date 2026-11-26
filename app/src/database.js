const db = require("./config/database");

function initializeDatabase() {
  db.exec(`
    -- Usuarios de la plataforma
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      email TEXT NOT NULL UNIQUE COLLATE NOCASE,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'user'
        CHECK (role IN ('admin', 'user')),
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );

    -- Activos tecnológicos
    CREATE TABLE IF NOT EXISTS assets (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      description TEXT,
      asset_type TEXT NOT NULL,
      owner_user_id INTEGER NOT NULL,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (owner_user_id)
        REFERENCES users(id)
        ON DELETE CASCADE
    );

    -- Documentos asociados a los activos
    CREATE TABLE IF NOT EXISTS documents (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      asset_id INTEGER NOT NULL,
      filename TEXT NOT NULL,
      storage_path TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (asset_id)
        REFERENCES assets(id)
        ON DELETE CASCADE
    );

    -- Auditoría de eventos
    CREATE TABLE IF NOT EXISTS audit_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      action TEXT NOT NULL,
      resource TEXT,
      ip_address TEXT,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id)
        REFERENCES users(id)
        ON DELETE SET NULL
    );

    -- Índices para consultas frecuentes
    CREATE INDEX IF NOT EXISTS idx_assets_owner
      ON assets(owner_user_id);

    CREATE INDEX IF NOT EXISTS idx_documents_asset
      ON documents(asset_id);

    CREATE INDEX IF NOT EXISTS idx_audit_logs_user
      ON audit_logs(user_id);

    CREATE INDEX IF NOT EXISTS idx_audit_logs_created
      ON audit_logs(created_at);
  `);

  console.log("Database schema initialized successfully");
}

module.exports = {
  db,
  initializeDatabase,
};
