process.env.DB_PATH = "./data/fleetsec.v09.test.db";

const express = require("express");
const request = require("supertest");
const bcrypt = require("bcryptjs");

const app = require("../../src/app");
const { db, initializeDatabase } = require("../../src/database");

const { createIdorLab } = require("../../src/vapt/v09-idor/idor.lab");

const ownerCredentials = {
  email: "v09.owner@fleetsec.local",
  password: "V09_Owner_Test_2026!",
};

const attackerCredentials = {
  email: "v09.attacker@fleetsec.local",
  password: "V09_Attacker_Test_2026!",
};

// Aplicación aislada para probar las rutas del laboratorio.
const labApp = express();
labApp.use("/api/idor", createIdorLab(db));

let ownerToken;
let attackerToken;
let ownerId;
let documentId;

beforeAll(async () => {
  initializeDatabase();

  // Limpiar exclusivamente la base de datos de V-09.
  db.exec(`
    DELETE FROM audit_logs;
    DELETE FROM documents;
    DELETE FROM assets;
    DELETE FROM users;
  `);

  const insertUser = db.prepare(`
    INSERT INTO users (name, email, password_hash, role)
    VALUES (?, ?, ?, 'user')
  `);

  const ownerResult = insertUser.run(
    "V09 Document Owner",
    ownerCredentials.email,
    bcrypt.hashSync(ownerCredentials.password, 10),
  );

  ownerId = Number(ownerResult.lastInsertRowid);

  insertUser.run(
    "V09 Unauthorized User",
    attackerCredentials.email,
    bcrypt.hashSync(attackerCredentials.password, 10),
  );

  // Crear un activo propiedad exclusiva del primer usuario.
  const assetResult = db
    .prepare(
      `
      INSERT INTO assets (name, description, asset_type, owner_user_id)
      VALUES (?, ?, ?, ?)
    `,
    )
    .run(
      "V09 Test Asset",
      "Controlled IDOR test fixture",
      "application",
      ownerId,
    );

  const assetId = Number(assetResult.lastInsertRowid);

  // Crear un documento ficticio asociado al activo del propietario.
  const documentResult = db
    .prepare(
      `
      INSERT INTO documents (asset_id, filename, storage_path)
      VALUES (?, ?, ?)
    `,
    )
    .run(
      assetId,
      "v09-confidential-test.txt",
      "fixtures/v09-confidential-test.txt",
    );

  documentId = Number(documentResult.lastInsertRowid);

  // Obtener tokens JWT mediante el endpoint real de autenticación.
  const ownerLogin = await request(app)
    .post("/api/auth/login")
    .send(ownerCredentials);

  expect(ownerLogin.status).toBe(200);
  ownerToken = ownerLogin.body.accessToken;

  const attackerLogin = await request(app)
    .post("/api/auth/login")
    .send(attackerCredentials);

  expect(attackerLogin.status).toBe(200);
  attackerToken = attackerLogin.body.accessToken;
});

afterAll(() => {
  db.close();
});

describe("V-09 - IDOR (CWE-639)", () => {
  test("should demonstrate unauthorized document access in the vulnerable endpoint", async () => {
    const response = await request(labApp)
      .get(`/api/idor/vulnerable/documents/${documentId}`)
      .set("Authorization", `Bearer ${attackerToken}`);

    expect(response.status).toBe(200);
    expect(response.body.document.filename).toBe("v09-confidential-test.txt");
    expect(response.body.document.owner_user_id).toBe(ownerId);
  });

  test("should deny document access to a non-owner in the secure endpoint", async () => {
    const response = await request(labApp)
      .get(`/api/idor/secure/documents/${documentId}`)
      .set("Authorization", `Bearer ${attackerToken}`);

    expect(response.status).toBe(404);
    expect(response.body.error).toBe("Document not found");
  });

  test("should allow the document owner to access their document", async () => {
    const response = await request(labApp)
      .get(`/api/idor/secure/documents/${documentId}`)
      .set("Authorization", `Bearer ${ownerToken}`);

    expect(response.status).toBe(200);
    expect(response.body.document.filename).toBe("v09-confidential-test.txt");
    expect(response.body.document.owner_user_id).toBe(ownerId);
  });

  test("should reject requests without authentication", async () => {
    const response = await request(labApp).get(
      `/api/idor/secure/documents/${documentId}`,
    );

    expect(response.status).toBe(401);
  });

  test("should return not found for an invalid document identifier", async () => {
    const response = await request(labApp)
      .get("/api/idor/secure/documents/invalid")
      .set("Authorization", `Bearer ${ownerToken}`);

    expect(response.status).toBe(404);
  });

  test("should allow the owner to access their document through the real API", async () => {
    const response = await request(app)
      .get(`/api/documents/${documentId}`)
      .set("Authorization", `Bearer ${ownerToken}`);

    expect(response.status).toBe(200);
    expect(response.body.document.filename).toBe("v09-confidential-test.txt");
    expect(response.body.document.owner_user_id).toBeUndefined();
    expect(response.body.document.storage_path).toBeUndefined();
  });

  test("should deny access to another user's document through the real API", async () => {
    const response = await request(app)
      .get(`/api/documents/${documentId}`)
      .set("Authorization", `Bearer ${attackerToken}`);

    expect(response.status).toBe(404);
    expect(response.body.error).toBe("Document not found");
  });

  test("should reject unauthenticated access through the real API", async () => {
    const response = await request(app).get(`/api/documents/${documentId}`);

    expect(response.status).toBe(401);
    expect(response.body.error).toBe("Authentication required");
  });

  test("should not reveal documents with invalid identifiers through the real API", async () => {
    const response = await request(app)
      .get("/api/documents/invalid")
      .set("Authorization", `Bearer ${ownerToken}`);

    expect(response.status).toBe(404);
    expect(response.body.error).toBe("Document not found");
  });
});
