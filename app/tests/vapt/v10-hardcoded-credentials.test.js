const {
  getHardcodedCredential,
  getEnvironmentCredential,
} = require("../../src/vapt/v10-hardcoded-credentials/credentials.lab");

describe("V-10 - CWE-798: Hardcoded Credentials", () => {
  describe("Implementación vulnerable", () => {
    test("expone una credencial incrustada en el código", () => {
      expect(getHardcodedCredential()).toBe(
        "V10_FAKE_DEMO_PASSWORD_2026",
      );
    });
  });

  describe("Implementación segura", () => {
    test("obtiene la credencial desde una variable externa", () => {
      const env = {
        V10_DEMO_PASSWORD: "External-Fake-Credential-2026",
      };

      expect(getEnvironmentCredential(env)).toBe(
        "External-Fake-Credential-2026",
      );
    });

    test("rechaza una variable de entorno ausente", () => {
      expect(() => getEnvironmentCredential({})).toThrow(
        "V10_DEMO_PASSWORD must be configured",
      );
    });

    test("rechaza una variable vacía", () => {
      expect(() =>
        getEnvironmentCredential({ V10_DEMO_PASSWORD: "   " }),
      ).toThrow("V10_DEMO_PASSWORD must be configured");
    });

    test("rechaza una configuración inválida", () => {
      expect(() => getEnvironmentCredential(null)).toThrow(TypeError);
      expect(() => getEnvironmentCredential([])).toThrow(TypeError);
    });
  });
});
