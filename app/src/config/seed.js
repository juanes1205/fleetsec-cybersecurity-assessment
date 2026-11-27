const bcrypt = require("bcryptjs");
const { db } = require("../database");
const logger = require("../utils/secure-logger");

const users = [
  {
    name: "FleetSec Administrator",
    email: "admin@fleetsec.local",
    password: process.env.SEED_ADMIN_PASSWORD,
    role: "admin",
  },
  {
    name: "Security Analyst",
    email: "analyst@fleetsec.local",
    password: process.env.SEED_ANALYST_PASSWORD,
    role: "user",
  },
  {
    name: "Standard User",
    email: "user@fleetsec.local",
    password: process.env.SEED_USER_PASSWORD,
    role: "user",
  },
];

function seedDatabase() {
  // Validar las contraseñas antes de iniciar la transacción.
  for (const user of users) {
    if (!user.password || user.password.length < 12) {
      throw new Error(
        "Configure una contraseña de al menos 12 caracteres para cada usuario inicial",
      );
    }
  }

  const insertUser = db.prepare(`
    INSERT OR IGNORE INTO users (name, email, password_hash, role)
    VALUES (?, ?, ?, ?)
  `);

  const findUser = db.prepare(`
    SELECT id, email FROM users WHERE email = ?
  `);

  const insertAsset = db.prepare(`
    INSERT INTO assets (name, description, asset_type, owner_user_id)
    SELECT ?, ?, ?, ?
    WHERE NOT EXISTS (
      SELECT 1 FROM assets
      WHERE name = ? AND owner_user_id = ?
    )
  `);

  const insertDocument = db.prepare(`
    INSERT INTO documents (asset_id, filename, storage_path)
    SELECT ?, ?, ?
    WHERE NOT EXISTS (
      SELECT 1 FROM documents
      WHERE asset_id = ? AND filename = ?
    )
  `);

  try {
    db.exec("BEGIN TRANSACTION");

    const createdUsers = {};

    for (const user of users) {
      const passwordHash = bcrypt.hashSync(user.password, 12);

      insertUser.run(user.name, user.email, passwordHash, user.role);

      const savedUser = findUser.get(user.email);
      createdUsers[user.email] = savedUser.id;
    }

    const adminId = createdUsers["admin@fleetsec.local"];
    const analystId = createdUsers["analyst@fleetsec.local"];

    insertAsset.run(
      "FleetSec Production Server",
      "Servidor ficticio de producción para pruebas de seguridad",
      "server",
      adminId,
      "FleetSec Production Server",
      adminId,
    );

    insertAsset.run(
      "Security Monitoring Platform",
      "Plataforma ficticia de monitoreo de seguridad",
      "application",
      analystId,
      "Security Monitoring Platform",
      analystId,
    );

    const asset = db
      .prepare(
        `
      SELECT id FROM assets
      WHERE name = ? AND owner_user_id = ?
    `,
      )
      .get("FleetSec Production Server", adminId);

    insertDocument.run(
      asset.id,
      "security-policy.txt",
      "documents/security-policy.txt",
      asset.id,
      "security-policy.txt",
    );

    db.exec("COMMIT");

    logger.info("Seed completed successfully", {
      usersProcessed: Object.keys(createdUsers).length,
    });
  } catch (error) {
    db.exec("ROLLBACK");
    throw error;
  }
}

module.exports = { seedDatabase };
