const {
  vulnerableUpdateUser,
  secureUpdateUser,
} = require("../../src/vapt/v05-mass-assignment/mass-assignment.lab");

describe("V-05 - Mass Assignment (CWE-915)", () => {
  let user;

  beforeEach(() => {
    user = {
      id: 1,
      nombre: "Usuario de prueba",
      email: "usuario@fleetsec.local",
      role: "user",
      activo: true,
    };
  });

  describe("Implementación vulnerable", () => {
    test("permite modificar el rol mediante asignación masiva", () => {
      const result = vulnerableUpdateUser(user, {
        nombre: "Usuario de prueba",
        role: "admin",
      });

      expect(result.role).toBe("admin");
      expect(user.role).toBe("admin");
    });
  });

  describe("Implementación segura", () => {
    test("permite actualizar los campos autorizados", () => {
      const result = secureUpdateUser(user, {
        nombre: "Nuevo nombre",
        email: "nuevo@fleetsec.local",
      });

      expect(result.nombre).toBe("Nuevo nombre");
      expect(result.email).toBe("nuevo@fleetsec.local");
    });

    test("impide modificar campos sensibles", () => {
      const result = secureUpdateUser(user, {
        nombre: "Nuevo nombre",
        role: "admin",
        activo: false,
        id: 999,
      });

      expect(result.nombre).toBe("Nuevo nombre");
      expect(result.role).toBe("user");
      expect(result.activo).toBe(true);
      expect(result.id).toBe(1);
    });

    test("ignora propiedades no autorizadas", () => {
      const result = secureUpdateUser(user, {
        departamento: "Administración",
        permisos: ["eliminar_usuarios"],
      });

      expect(result.departamento).toBeUndefined();
      expect(result.permisos).toBeUndefined();
    });

    test("no modifica el objeto original", () => {
      const originalUser = { ...user };

      secureUpdateUser(user, {
        nombre: "Nombre actualizado",
        role: "admin",
      });

      expect(user).toEqual(originalUser);
    });
  });

  describe("Validación de entradas", () => {
    test("rechaza un usuario inválido", () => {
      expect(() => secureUpdateUser(null, { nombre: "Prueba" })).toThrow(
        TypeError,
      );
    });

    test("rechaza datos de entrada nulos", () => {
      expect(() => secureUpdateUser(user, null)).toThrow(TypeError);
    });

    test("rechaza arreglos como datos de entrada", () => {
      expect(() => secureUpdateUser(user, ["admin"])).toThrow(TypeError);
    });

    test("rechaza arreglos como usuario", () => {
      expect(() => secureUpdateUser([], { nombre: "Prueba" })).toThrow(
        TypeError,
      );
    });
  });
});
