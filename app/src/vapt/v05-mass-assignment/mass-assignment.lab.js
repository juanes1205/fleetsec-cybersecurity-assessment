const ALLOWED_USER_FIELDS = ["nombre", "email"];

function validateInput(user, input) {
  if (!user || typeof user !== "object" || Array.isArray(user)) {
    throw new TypeError("El usuario debe ser un objeto válido");
  }

  if (!input || typeof input !== "object" || Array.isArray(input)) {
    throw new TypeError("Los datos de entrada deben ser un objeto válido");
  }
}

/**
 * Simulación vulnerable:
 * asigna todas las propiedades recibidas sin verificar
 * si el usuario tiene autorización para modificarlas.
 */
function vulnerableUpdateUser(user, input) {
  validateInput(user, input);

  return Object.assign(user, input);
}

/**
 * Implementación segura:
 * únicamente permite actualizar los campos incluidos
 * en la lista explícita de propiedades autorizadas.
 */
function secureUpdateUser(user, input) {
  validateInput(user, input);

  const allowedFields = Object.fromEntries(
    Object.entries(input).filter(([key]) => ALLOWED_USER_FIELDS.includes(key)),
  );

  return {
    ...user,
    ...allowedFields,
  };
}

module.exports = {
  vulnerableUpdateUser,
  secureUpdateUser,
};
