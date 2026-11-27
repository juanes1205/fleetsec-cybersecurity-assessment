// Configuración aislada para la prueba de integración V-07.
process.env.DB_PATH = "./data/fleetsec.v07.test.db";
process.env.LOGIN_RATE_LIMIT_WINDOW_MS = "60000";
process.env.LOGIN_RATE_LIMIT_MAX = "5";

const request = require("supertest");
const bcrypt = require("bcryptjs");

const app = require("../../src/app");
const { db, initializeDatabase } = require("../../src/database");

const credentials = {
  email: "v07.test@fleetsec.local",
  password: "V07_Test_Password_2026!",
};

beforeAll(() => {
  initializeDatabase();

  db.exec(`
    DELETE FROM audit_logs;
    DELETE FROM documents;
    DELETE FROM assets;
    DELETE FROM users;
  `);

  const insertUser = db.prepare(`
    INSERT INTO users (name, email, password_hash, role)
    VALUES (?, ?, ?, ?)
  `);

  insertUser.run(
    "V07 Integration User",
    credentials.email,
    bcrypt.hashSync(credentials.password, 10),
    "user",
  );
});

afterAll(() => {
  db.close();
});

describe("V-07 - Rate Limiting en la API real", () => {
  test("permite login legítimo y bloquea intentos excesivos", async () => {
    // Primer intento: autenticación legítima.
    const legitimateResponse = await request(app)
      .post("/api/auth/login")
      .send(credentials);

    expect(legitimateResponse.status).toBe(200);
    expect(legitimateResponse.body.accessToken).toBeDefined();

    // Siguientes cuatro intentos: credenciales incorrectas.
    for (let i = 0; i < 4; i++) {
      const response = await request(app)
        .post("/api/auth/login")
        .send({
          email: credentials.email,
          password: "Incorrect_Password_2026!",
        });

      expect(response.status).toBe(401);
      expect(response.body.error).toBe("Invalid credentials");
    }

    // Sexta solicitud total: debe ser bloqueada.
    const blockedResponse = await request(app)
      .post("/api/auth/login")
      .send({
        email: credentials.email,
        password: "Incorrect_Password_2026!",
      });

    expect(blockedResponse.status).toBe(429);
    expect(blockedResponse.body.error).toBe(
      "Too many login attempts. Please try again later.",
    );

    expect(blockedResponse.headers["ratelimit"]).toBeDefined();
  });
});
