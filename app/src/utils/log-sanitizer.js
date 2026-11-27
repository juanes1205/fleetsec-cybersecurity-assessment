const SENSITIVE_KEYS =
  /(^name$|first.?name|last.?name|full.?name|user.?name|display.?name|password|passwd|token|authorization|secret|api.?key|email|phone|mobile|document|identification|national.?id|birth.?date|date.?of.?birth|^dob$|address|ip.?address)/i;

/**
 * Sanitiza texto que pueda contener información personal
 * o credenciales incrustadas en mensajes de log.
 */
function sanitizeText(value) {
  if (typeof value !== "string") {
    return value;
  }

  return value
    .replace(/\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi, "[EMAIL_REDACTED]")
    .replace(
      /\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g,
      "[JWT_REDACTED]",
    )
    .replace(/\bBearer\s+[A-Za-z0-9._~+/=-]+/gi, "Bearer [TOKEN_REDACTED]")
    .replace(
      /\b(password|passwd|secret|api[_-]?key)\s*[:=]\s*["']?[^"' \t,;]+/gi,
      "$1=[REDACTED]",
    );
}

/**
 * Sanitiza recursivamente objetos, arreglos y errores.
 * Detecta ciclos reales sin marcar referencias reutilizadas
 * como si fueran circulares.
 */
function sanitizeLogData(value, seen = new WeakSet()) {
  if (typeof value === "string") {
    return sanitizeText(value);
  }

  if (value === null || typeof value !== "object") {
    return value;
  }

  if (seen.has(value)) {
    return "[Circular]";
  }

  seen.add(value);

  if (value instanceof Error) {
    const sanitizedError = {
      name: sanitizeText(value.name),
      message: sanitizeText(value.message),
    };

    seen.delete(value);
    return sanitizedError;
  }

  if (Array.isArray(value)) {
    const sanitizedArray = value.map((item) => sanitizeLogData(item, seen));

    seen.delete(value);
    return sanitizedArray;
  }

  const sanitized = {};

  for (const [key, item] of Object.entries(value)) {
    if (SENSITIVE_KEYS.test(key)) {
      sanitized[key] = "[REDACTED]";
    } else {
      sanitized[key] = sanitizeLogData(item, seen);
    }
  }

  seen.delete(value);
  return sanitized;
}

module.exports = {
  sanitizeText,
  sanitizeLogData,
};
