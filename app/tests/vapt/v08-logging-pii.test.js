const request = require("supertest");

const {
  createLoggingLab,
} = require("../../src/vapt/v08-logging-pii/logging-pii.lab");
const logger = require("../../src/utils/secure-logger");

describe("V-08 - Logging de información personal (CWE-359)", () => {
  let app;

  const fakeUserData = {
    userId: 123,
    name: "Usuario Ficticio",
    email: "usuario@fleetsec.local",
    phone: "3001234567",
    documentNumber: "123456789",
    password: "Clave_Ficticia_2026",
    token: "token-ficticio-123",
  };

  beforeEach(() => {
    app = createLoggingLab();
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  test("demuestra que el endpoint vulnerable expone datos personales", async () => {
    const consoleSpy = jest.spyOn(console, "log").mockImplementation(() => {});

    const response = await request(app)
      .post("/vulnerable-log")
      .send(fakeUserData);

    expect(response.status).toBe(200);
    expect(consoleSpy).toHaveBeenCalled();

    const loggedOutput = JSON.stringify(consoleSpy.mock.calls);

    expect(loggedOutput).toContain(fakeUserData.email);
    expect(loggedOutput).toContain(fakeUserData.phone);
    expect(loggedOutput).toContain(fakeUserData.documentNumber);
    expect(loggedOutput).toContain(fakeUserData.password);
    expect(loggedOutput).toContain(fakeUserData.name);
  });

  test("redacta los datos personales en el endpoint seguro", async () => {
    const consoleSpy = jest.spyOn(console, "log").mockImplementation(() => {});

    const response = await request(app).post("/secure-log").send(fakeUserData);

    expect(response.status).toBe(200);
    expect(consoleSpy).toHaveBeenCalled();

    const loggedOutput = consoleSpy.mock.calls.flat().join(" ");

    expect(loggedOutput).toContain("[REDACTED]");
    expect(loggedOutput).not.toContain(fakeUserData.email);
    expect(loggedOutput).not.toContain(fakeUserData.phone);
    expect(loggedOutput).not.toContain(fakeUserData.documentNumber);
    expect(loggedOutput).not.toContain(fakeUserData.password);
    expect(loggedOutput).not.toContain(fakeUserData.token);
    expect(loggedOutput).not.toContain(fakeUserData.name);
    expect(loggedOutput).toContain('"userId":123');
  });

  test("redacta información sensible en los niveles info, warn y error", () => {
    const infoSpy = jest.spyOn(console, "log").mockImplementation(() => {});
    const warnSpy = jest.spyOn(console, "warn").mockImplementation(() => {});
    const errorSpy = jest.spyOn(console, "error").mockImplementation(() => {});

    logger.info("Authentication event", fakeUserData);
    logger.warn("Suspicious activity", fakeUserData);
    logger.error("Authentication failure", {
      ...fakeUserData,
      error: new Error(`Failure for ${fakeUserData.email}`),
    });

    const outputs = [
      ...infoSpy.mock.calls,
      ...warnSpy.mock.calls,
      ...errorSpy.mock.calls,
    ]
      .flat()
      .join(" ");

    expect(infoSpy).toHaveBeenCalledTimes(1);
    expect(warnSpy).toHaveBeenCalledTimes(1);
    expect(errorSpy).toHaveBeenCalledTimes(1);

    expect(outputs).toContain("[REDACTED]");
    expect(outputs).toContain("[EMAIL_REDACTED]");

    expect(outputs).not.toContain(fakeUserData.email);
    expect(outputs).not.toContain(fakeUserData.phone);
    expect(outputs).not.toContain(fakeUserData.documentNumber);
    expect(outputs).not.toContain(fakeUserData.password);
    expect(outputs).not.toContain(fakeUserData.token);
  });

  test("mantiene el flujo legítimo del endpoint seguro", async () => {
    const consoleSpy = jest.spyOn(console, "log").mockImplementation(() => {});

    const response = await request(app).post("/secure-log").send({
      userId: 123,
      action: "login",
    });

    expect(response.status).toBe(200);
    expect(response.body).toEqual({
      message: "Secure log generated",
    });
    expect(consoleSpy).toHaveBeenCalled();
  });
});
