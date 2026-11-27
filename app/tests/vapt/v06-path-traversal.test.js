const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const express = require("express");
const request = require("supertest");

const {
  vulnerableReadFile,
  secureReadFile,
} = require("../../src/vapt/v06-path-traversal/path-traversal.lab");

describe("V-06 - Path Traversal (CWE-22)", () => {
  let tempRoot;
  let publicDir;
  let privateDir;
  let app;

  beforeAll(() => {
    tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "fleetsec-v06-"));

    publicDir = path.join(tempRoot, "public");
    privateDir = path.join(tempRoot, "private");

    fs.mkdirSync(publicDir);
    fs.mkdirSync(privateDir);

    fs.writeFileSync(
      path.join(publicDir, "vehicle.txt"),
      "FLEETSEC: archivo público de prueba",
    );

    fs.writeFileSync(
      path.join(privateDir, "secret.txt"),
      "FLEETSEC-LAB-ONLY: archivo ficticio confidencial",
    );

    app = express();

    // Endpoint vulnerable: solo existe dentro de este laboratorio.
    app.get("/api/files-vulnerable", (req, res) => {
      try {
        const content = vulnerableReadFile(publicDir, req.query.file);
        return res.status(200).send(content);
      } catch {
        return res.status(400).json({ error: "No se pudo leer el archivo" });
      }
    });

    // Endpoint corregido: solo existe dentro de este laboratorio.
    app.get("/api/files-secure", (req, res) => {
      try {
        const content = secureReadFile(publicDir, req.query.file);
        return res.status(200).send(content);
      } catch (error) {
        const forbidden = error.message.includes("Acceso denegado");
        const status = forbidden ? 403 : 400;

        return res.status(status).json({
          error: forbidden ? "Acceso denegado" : "Solicitud no válida",
        });
      }
    });
  });

  afterAll(() => {
    if (tempRoot) {
      fs.rmSync(tempRoot, { recursive: true, force: true });
    }
  });

  test("demuestra que el endpoint vulnerable permite leer un archivo público", async () => {
    const response = await request(app)
      .get("/api/files-vulnerable")
      .query({ file: "vehicle.txt" });

    expect(response.status).toBe(200);
    expect(response.text).toBe("FLEETSEC: archivo público de prueba");
  });

  test("demuestra Path Traversal leyendo un archivo ficticio fuera del directorio permitido", async () => {
    const response = await request(app)
      .get("/api/files-vulnerable")
      .query({ file: "../private/secret.txt" });

    expect(response.status).toBe(200);
    expect(response.text).toBe(
      "FLEETSEC-LAB-ONLY: archivo ficticio confidencial",
    );
  });

  test("permite leer archivos públicos mediante el endpoint corregido", async () => {
    const response = await request(app)
      .get("/api/files-secure")
      .query({ file: "vehicle.txt" });

    expect(response.status).toBe(200);
    expect(response.text).toBe("FLEETSEC: archivo público de prueba");
  });

  test("bloquea Path Traversal mediante el endpoint corregido", async () => {
    const response = await request(app)
      .get("/api/files-secure")
      .query({ file: "../private/secret.txt" });

    expect(response.status).toBe(403);
    expect(response.body.error).toBe("Acceso denegado");
    expect(response.text).not.toContain("FLEETSEC-LAB-ONLY");
  });

  test("rechaza rutas absolutas", () => {
    expect(() =>
      secureReadFile(publicDir, path.join(privateDir, "secret.txt")),
    ).toThrow("El nombre del archivo no es válido");
  });

  test("rechaza nombres de archivo vacíos", () => {
    expect(() => secureReadFile(publicDir, "")).toThrow(
      "El nombre del archivo no es válido",
    );
  });

  test("rechaza valores que no sean cadenas", () => {
    expect(() => secureReadFile(publicDir, null)).toThrow(
      "El nombre del archivo no es válido",
    );
  });

  test("rechaza archivos inexistentes", () => {
    expect(() => secureReadFile(publicDir, "missing.txt")).toThrow(
      "Archivo no encontrado o ruta no permitida",
    );
  });
});
