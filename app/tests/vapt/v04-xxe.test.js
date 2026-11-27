const {
  vulnerableParseXml,
  secureParseXml,
} = require("../../src/vapt/v04-xxe/xxe.lab");

describe("V-04 - XXE (CWE-611)", () => {
  const fixtures = {
    "secret.txt": "DATO_FICTICIO_CONFIDENCIAL",
  };

  const maliciousXml = `<?xml version="1.0"?>
<!DOCTYPE usuario [
  <!ENTITY informacion SYSTEM "fixture://secret.txt">
]>
<usuario>&informacion;</usuario>`;

  const normalXml = `<?xml version="1.0"?>
<usuario>
  <nombre>Usuario de prueba</nombre>
  <correo>usuario@example.test</correo>
</usuario>`;

  describe("Simulación vulnerable", () => {
    test("demuestra la expansión de una entidad externa ficticia", () => {
      const result = vulnerableParseXml(maliciousXml, fixtures);

      expect(result).toContain("DATO_FICTICIO_CONFIDENCIAL");
      expect(result).not.toContain("&informacion;");
    });

    test("rechaza recursos ficticios inexistentes", () => {
      expect(() => vulnerableParseXml(maliciousXml, {})).toThrow(
        "External entity resource not found",
      );
    });

    test("acepta XML normal sin DTD", () => {
      expect(vulnerableParseXml(normalXml)).toBe(normalXml);
    });

    test("rechaza entradas que no son cadenas", () => {
      expect(() => vulnerableParseXml(null)).toThrow("XML must be a string");
    });
  });

  describe("Implementación segura con fast-xml-parser", () => {
    test("bloquea documentos que contienen DOCTYPE", () => {
      expect(() => secureParseXml(maliciousXml)).toThrow(
        "DOCTYPE declarations are not allowed",
      );
    });

    test("bloquea declaraciones ENTITY", () => {
      const xml = `<?xml version="1.0"?>
<!ENTITY informacion "dato">
<usuario>&informacion;</usuario>`;

      expect(() => secureParseXml(xml)).toThrow(
        "ENTITY declarations are not allowed",
      );
    });

    test("analiza correctamente documentos XML normales", () => {
      const result = secureParseXml(normalXml);

      expect(result.usuario.nombre).toBe("Usuario de prueba");
      expect(result.usuario.correo).toBe("usuario@example.test");
    });

    test("rechaza entradas que no son cadenas", () => {
      expect(() => secureParseXml(null)).toThrow("XML must be a string");
    });

    test("rechaza documentos XML malformados", () => {
      const invalidXml = "<usuario><nombre>Prueba</usuario>";

      expect(() => secureParseXml(invalidXml)).toThrow("Invalid XML document");
    });

    test("rechaza documentos que superan el tamaño máximo", () => {
      const oversizedXml = `<usuario>${"A".repeat(65 * 1024)}</usuario>`;

      expect(() => secureParseXml(oversizedXml)).toThrow(
        "XML size limit exceeded",
      );
    });

    test("conserva referencias de entidades predefinidas con processEntities desactivado", () => {
      const xml = "<usuario>&amp;</usuario>";
      const result = secureParseXml(xml);

      expect(result.usuario).toBe("&amp;");
    });
  });
});
