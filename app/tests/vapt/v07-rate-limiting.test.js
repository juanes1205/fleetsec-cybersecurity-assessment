const request = require("supertest");

const {
  createVulnerableApp,
  createSecureApp,
  LAB_CREDENTIALS,
  RATE_LIMIT_MAX_REQUESTS,
} = require("../../src/vapt/v07-rate-limiting/rate-limit.lab");

describe("V-07 - Missing Rate Limiting (CWE-307)", () => {
  describe("Endpoint vulnerable", () => {
    let app;

    beforeEach(() => {
      app = createVulnerableApp();
    });

    test("permite múltiples intentos fallidos sin aplicar limitación", async () => {
      const attempts = [];

      for (let i = 0; i < 5; i++) {
        attempts.push(
          request(app).post("/api/auth/login").send({
            email: LAB_CREDENTIALS.email,
            password: "Wrong_Password_2026!",
          }),
        );
      }

      const responses = await Promise.all(attempts);

      expect(responses).toHaveLength(5);

      responses.forEach((response) => {
        expect(response.status).toBe(401);
        expect(response.body.error).toBe("Invalid credentials");
      });
    });

    test("permite autenticación legítima", async () => {
      const response = await request(app)
        .post("/api/auth/login")
        .send(LAB_CREDENTIALS);

      expect(response.status).toBe(200);
      expect(response.body.message).toBe("Authentication successful");
    });
  });

  describe("Endpoint seguro", () => {
    let app;

    beforeEach(() => {
      app = createSecureApp();
    });

    test("permite solicitudes dentro del límite configurado", async () => {
      for (let i = 0; i < RATE_LIMIT_MAX_REQUESTS; i++) {
        const response = await request(app).post("/api/auth/login").send({
          email: LAB_CREDENTIALS.email,
          password: "Wrong_Password_2026!",
        });

        expect(response.status).toBe(401);
      }
    });

    test("bloquea solicitudes que superan el límite con HTTP 429", async () => {
      const attempts = [];

      for (let i = 0; i < RATE_LIMIT_MAX_REQUESTS + 1; i++) {
        attempts.push(
          request(app).post("/api/auth/login").send({
            email: LAB_CREDENTIALS.email,
            password: "Wrong_Password_2026!",
          }),
        );
      }

      const responses = await Promise.all(attempts);

      expect(
        responses.filter((response) => response.status === 401),
      ).toHaveLength(RATE_LIMIT_MAX_REQUESTS);

      const blockedResponse = responses.find(
        (response) => response.status === 429,
      );

      expect(blockedResponse).toBeDefined();
      expect(blockedResponse.body.error).toBe(
        "Too many login attempts. Please try again later.",
      );
    });

    test("incluye encabezados informativos del rate limiter", async () => {
      const response = await request(app)
        .post("/api/auth/login")
        .send(LAB_CREDENTIALS);

      expect(response.headers["ratelimit"]).toBeDefined();
    });
  });
});
