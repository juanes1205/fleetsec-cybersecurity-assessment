const { XMLParser, XMLValidator } = require("fast-xml-parser");

const MAX_XML_SIZE = 64 * 1024;

// Simulación vulnerable de resolución de entidades externas.
// Solo utiliza recursos ficticios proporcionados en memoria.
function vulnerableParseXml(xml, fixtures = {}) {
  if (typeof xml !== "string") {
    throw new Error("XML must be a string");
  }

  const doctypeMatch = xml.match(/<!DOCTYPE\s+[\w:.-]+\s*\[([\s\S]*?)\]\s*>/i);

  if (!doctypeMatch) {
    return xml;
  }

  const declarations = doctypeMatch[1];

  const entityRegex =
    /<!ENTITY\s+([a-zA-Z_][\w.-]*)\s+SYSTEM\s+["']fixture:\/\/([^"']+)["']\s*>/gi;

  let result = xml;

  for (const match of declarations.matchAll(entityRegex)) {
    const entityName = match[1];
    const fixtureName = match[2];

    if (!Object.hasOwn(fixtures, fixtureName)) {
      throw new Error("External entity resource not found");
    }

    result = result.replaceAll(`&${entityName};`, fixtures[fixtureName]);
  }

  return result.replace(doctypeMatch[0], "");
}

// Parser XML real con política de seguridad.
// Rechaza DTD y entidades antes de analizar el documento.
function secureParseXml(xml) {
  if (typeof xml !== "string") {
    throw new Error("XML must be a string");
  }

  if (Buffer.byteLength(xml, "utf8") > MAX_XML_SIZE) {
    throw new Error("XML size limit exceeded");
  }

  if (/<!DOCTYPE\b/i.test(xml)) {
    throw new Error("DOCTYPE declarations are not allowed");
  }

  if (/<!ENTITY\b/i.test(xml)) {
    throw new Error("ENTITY declarations are not allowed");
  }

  const validation = XMLValidator.validate(xml);

  if (validation !== true) {
    throw new Error("Invalid XML document");
  }

  const parser = new XMLParser({
    processEntities: false,
    ignoreAttributes: false,
    allowBooleanAttributes: false,
    trimValues: true,
  });

  return parser.parse(xml);
}

module.exports = {
  vulnerableParseXml,
  secureParseXml,
};
