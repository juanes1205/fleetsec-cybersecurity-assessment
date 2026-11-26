const { DatabaseSync } = require("node:sqlite");

const {
  vulnerableSearch,
  secureSearch,
} = require("../../src/vapt/v01-sqli/sqli.lab");

describe("V-01 - SQL Injection (CWE-89)", () => {
  let db;

  beforeEach(() => {
    db = new DatabaseSync(":memory:");

    db.exec(`
      CREATE TABLE assets (
        id INTEGER PRIMARY KEY,
        name TEXT NOT NULL,
        description TEXT
      );

      INSERT INTO assets (name, description)
      VALUES
        ('Servidor de pruebas', 'Activo ficticio'),
        ('Firewall de pruebas', 'Activo ficticio');
    `);
  });

  afterEach(() => {
    db.close();
  });

  test("demuestra que la consulta vulnerable altera su lógica", () => {
    const normalResult = vulnerableSearch(db, "Servidor de pruebas");

    const manipulatedResult = vulnerableSearch(db, "' OR 1=1 -- ");

    expect(normalResult).toHaveLength(1);
    expect(manipulatedResult).toHaveLength(2);
  });

  test("la consulta parametrizada no permite alterar su lógica", () => {
    const normalResult = secureSearch(db, "Servidor de pruebas");

    const manipulatedResult = secureSearch(db, "' OR 1=1 -- ");

    expect(normalResult).toHaveLength(1);
    expect(manipulatedResult).toHaveLength(0);
  });
});
