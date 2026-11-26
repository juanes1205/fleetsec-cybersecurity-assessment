require("dotenv").config();

const jwt = require("jsonwebtoken");

const {
  JWT_SECRET,
  JWT_ISSUER,
  JWT_AUDIENCE,
} = require("../../src/config/auth");

const { authenticateToken } = require("../../src/middleware/auth.middleware");

const { unsafeDecodeToken } = require("../../src/vapt/v02-jwt/jwt.lab");

function createToken(overrides = {}, options = {}) {
  const payload = {
    email: "admin@fleetsec.local",
    role: "admin",
    ...overrides,
  };

  return jwt.sign(payload, options.secret || JWT_SECRET, {
    algorithm: options.algorithm || "HS256",
    subject: "1",
    issuer: options.issuer || JWT_ISSUER,
    audience: options.audience || JWT_AUDIENCE,
    expiresIn: options.expiresIn || "5m",
  });
}

function executeMiddleware(token) {
  const req = {
    headers: token ? { authorization: `Bearer ${token}` } : {},
  };

  const res = {
    statusCode: null,
    body: null,

    status(code) {
      this.statusCode = code;
      return this;
    },

    json(body) {
      this.body = body;
      return this;
    },
  };

  const next = jest.fn();

  authenticateToken(req, res, next);

  return { req, res, next };
}

describe("V-02 - JWT / Broken Authentication", () => {
  test("demuestra que decodificar un JWT no verifica su autenticidad", () => {
    const forgedToken = createToken(
      {},
      { secret: "attacker-controlled-secret-123456" },
    );

    const decodedPayload = unsafeDecodeToken(forgedToken);

    expect(decodedPayload).not.toBeNull();
    expect(decodedPayload.email).toBe("admin@fleetsec.local");
    expect(decodedPayload.role).toBe("admin");
  });

  test("debe rechazar un token firmado con un secreto diferente", () => {
    const forgedToken = createToken(
      {},
      { secret: "attacker-controlled-secret-123456" },
    );

    const { res, next } = executeMiddleware(forgedToken);

    expect(res.statusCode).toBe(401);
    expect(next).not.toHaveBeenCalled();
  });

  test("debe rechazar un token con firma manipulada", () => {
    const token = createToken();
    const parts = token.split(".");

    // parts[2] = `${parts[2].slice(0, -1)}x`;
    parts[2] = (parts[2][0] === "a" ? "b" : "a") + parts[2].slice(1);

    const manipulatedToken = parts.join(".");

    const { res, next } = executeMiddleware(manipulatedToken);

    expect(res.statusCode).toBe(401);
    expect(next).not.toHaveBeenCalled();
  });

  test("debe rechazar un token expirado", () => {
    const expiredToken = createToken({}, { expiresIn: "-1s" });

    const { res, next } = executeMiddleware(expiredToken);

    expect(res.statusCode).toBe(401);
    expect(next).not.toHaveBeenCalled();
  });

  test("debe rechazar algoritmos no permitidos", () => {
    const token = createToken({}, { algorithm: "HS384" });

    const { res, next } = executeMiddleware(token);

    expect(res.statusCode).toBe(401);
    expect(next).not.toHaveBeenCalled();
  });

  test("debe rechazar un issuer incorrecto", () => {
    const token = createToken({}, { issuer: "untrusted-issuer" });

    const { res, next } = executeMiddleware(token);

    expect(res.statusCode).toBe(401);
    expect(next).not.toHaveBeenCalled();
  });

  test("debe rechazar un audience incorrecto", () => {
    const token = createToken({}, { audience: "untrusted-client" });

    const { res, next } = executeMiddleware(token);

    expect(res.statusCode).toBe(401);
    expect(next).not.toHaveBeenCalled();
  });

  test("debe aceptar un token válido", () => {
    const token = createToken();

    const { req, res, next } = executeMiddleware(token);

    expect(next).toHaveBeenCalledTimes(1);
    expect(res.statusCode).toBeNull();
    expect(req.user).toEqual({
      id: 1,
      email: "admin@fleetsec.local",
      role: "admin",
    });
  });
});
