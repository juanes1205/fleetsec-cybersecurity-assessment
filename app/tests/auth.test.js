// Configurar una base de datos independiente para las pruebas.
process.env.DB_PATH = "./data/fleetsec.test.db";

const request = require("supertest");
const bcrypt = require("bcryptjs");

const app = require("../src/app");
const { db, initializeDatabase } = require("../src/database");

// Credenciales ficticias exclusivas del entorno de pruebas.
const adminCredentials = {
  email: "admin.test@fleetsec.local",
  password: "Test_Admin_2026!",
};

const userCredentials = {
  email: "user.test@fleetsec.local",
  password: "Test_User_2026!",
};

let adminToken;
let userToken;

beforeAll(async () => {
  // Crear las tablas de la base de datos de pruebas.
  initializeDatabase();
  // Limpiar los datos de ejecuciones anteriores.
  // Esta conexión utiliza exclusivamente fleetsec.test.db.
  db.exec(`
    DELETE FROM audit_logs;
    DELETE FROM documents;
    DELETE FROM assets;
    DELETE FROM users;
  `);

  // Crear usuarios de prueba con contraseñas cifradas.
  const insertUser = db.prepare(`
    INSERT INTO users (name, email, password_hash, role)
    VALUES (?, ?, ?, ?)
  `);

  insertUser.run(
    "Test Administrator",
    adminCredentials.email,
    bcrypt.hashSync(adminCredentials.password, 10),
    "admin",
  );

  insertUser.run(
    "Test User",
    userCredentials.email,
    bcrypt.hashSync(userCredentials.password, 10),
    "user",
  );

  // Obtener el token del administrador.
  const adminResponse = await request(app)
    .post("/api/auth/login")
    .send(adminCredentials);

  adminToken = adminResponse.body.accessToken;

  // Obtener el token del usuario normal.
  const userResponse = await request(app)
    .post("/api/auth/login")
    .send(userCredentials);

  userToken = userResponse.body.accessToken;
});

afterAll(() => {
  // Cerrar la conexión de la base de datos de pruebas.
  db.close();
});

describe("Authentication API", () => {
  test("should authenticate a user with valid credentials", async () => {
    const response = await request(app)
      .post("/api/auth/login")
      .send(adminCredentials);

    expect(response.status).toBe(200);
    expect(response.body.message).toBe("Authentication successful");
    expect(response.body.accessToken).toBeDefined();
    expect(response.body.tokenType).toBe("Bearer");
    expect(response.body.user.role).toBe("admin");
    expect(response.body.user.password_hash).toBeUndefined();
  });

  test("should reject invalid credentials", async () => {
    const response = await request(app).post("/api/auth/login").send({
      email: adminCredentials.email,
      password: "Incorrect_Password_2026!",
    });

    expect(response.status).toBe(401);
    expect(response.body.error).toBe("Invalid credentials");
  });

  test("should return the authenticated user", async () => {
    const response = await request(app)
      .get("/api/auth/me")
      .set("Authorization", `Bearer ${adminToken}`);

    expect(response.status).toBe(200);
    expect(response.body.user.email).toBe(adminCredentials.email);
    expect(response.body.user.role).toBe("admin");
    expect(response.body.user.password_hash).toBeUndefined();
  });

  test("should reject requests without a token", async () => {
    const response = await request(app).get("/api/auth/me");

    expect(response.status).toBe(401);
    expect(response.body.error).toBe("Authentication required");
  });
});

describe("Role-based access control", () => {
  test("should allow administrators to access the dashboard", async () => {
    const response = await request(app)
      .get("/api/admin/dashboard")
      .set("Authorization", `Bearer ${adminToken}`);

    expect(response.status).toBe(200);
    expect(response.body.message).toBe("Administrator access granted");
    expect(response.body.user.role).toBe("admin");
  });

  test("should deny access to regular users", async () => {
    const response = await request(app)
      .get("/api/admin/dashboard")
      .set("Authorization", `Bearer ${userToken}`);

    expect(response.status).toBe(403);
    expect(response.body.error).toBe("Insufficient permissions");
  });

  test("should deny access without authentication", async () => {
    const response = await request(app).get("/api/admin/dashboard");

    expect(response.status).toBe(401);
    expect(response.body.error).toBe("Authentication required");
  });
});
