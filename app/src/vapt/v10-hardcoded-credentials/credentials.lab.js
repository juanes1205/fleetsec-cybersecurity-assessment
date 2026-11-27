/**
 * V-10 - CWE-798: Hardcoded Credentials.
 *
 * Laboratorio controlado con una credencial ficticia.
 * No utilizar esta implementación en producción.
 */

// VULNERABLE: credencial ficticia incrustada en el código.
function getHardcodedCredential() {
  return "V10_FAKE_DEMO_PASSWORD_2026";
}

// SEGURO: obtiene la credencial desde una fuente externa.
// No utiliza credenciales por defecto ni valores de fallback.
function getEnvironmentCredential(env) {
  if (!env || typeof env !== "object" || Array.isArray(env)) {
    throw new TypeError("A valid environment configuration is required");
  }

  const credential = env.V10_DEMO_PASSWORD;

  if (typeof credential !== "string" || credential.trim().length === 0) {
    throw new Error("V10_DEMO_PASSWORD must be configured");
  }

  return credential;
}

module.exports = {
  getHardcodedCredential,
  getEnvironmentCredential,
};
