const dns = require("node:dns").promises;
const https = require("node:https");
const { EventEmitter } = require("node:events");

const http = require("node:http");

const {
  vulnerableFetch,
  secureFetch,
  validateDestination,
  isPublicIp,
  resolveAndValidateHost,
} = require("../../src/vapt/v03-ssrf/ssrf.lab");

describe("V-03 - SSRF (CWE-918)", () => {
  let server;
  let serverUrl;

  beforeAll(async () => {
    server = http.createServer((req, res) => {
      res.writeHead(200, {
        "Content-Type": "text/plain",
      });

      res.end("Contenido ficticio del servidor de pruebas");
    });

    await new Promise((resolve) => {
      server.listen(0, "127.0.0.1", resolve);
    });

    const address = server.address();

    serverUrl = `http://127.0.0.1:${address.port}`;
  });

  afterAll(async () => {
    if (server) {
      await new Promise((resolve, reject) => {
        server.close((error) => {
          if (error) reject(error);
          else resolve();
        });
      });
    }
  });

  test("debe identificar una IPv4 pública", () => {
    expect(isPublicIp("8.8.8.8")).toBe(true);
  });

  test("debe rechazar una IPv4 privada", () => {
    expect(isPublicIp("192.168.1.10")).toBe(false);
  });

  test("debe rechazar loopback IPv4", () => {
    expect(isPublicIp("127.0.0.1")).toBe(false);
  });

  test("debe rechazar link-local IPv4", () => {
    expect(isPublicIp("169.254.10.20")).toBe(false);
  });

  test("debe rechazar loopback IPv6", () => {
    expect(isPublicIp("::1")).toBe(false);
  });

  test("debe rechazar IPv6 privada", () => {
    expect(isPublicIp("fc00::1")).toBe(false);
  });

  test("debe rechazar IPv6 link-local", () => {
    expect(isPublicIp("fe80::1")).toBe(false);
  });

  test("debe rechazar destinos con direcciones DNS no públicas", async () => {
    const lookupSpy = jest.spyOn(dns, "lookup").mockResolvedValue([
      {
        address: "127.0.0.1",
        family: 4,
      },
    ]);

    try {
      await expect(resolveAndValidateHost("api.example.com")).rejects.toThrow(
        "Destination resolves to a non-public IP",
      );
    } finally {
      lookupSpy.mockRestore();
    }
  });

  test("secureFetch debe bloquear una conexión cuando DNS resuelve a una IP privada", async () => {
    const lookupSpy = jest.spyOn(dns, "lookup").mockResolvedValue([
      {
        address: "127.0.0.1",
        family: 4,
      },
    ]);

    const requestSpy = jest.spyOn(https, "request");

    try {
      await expect(secureFetch("https://api.example.com")).rejects.toThrow(
        "Destination resolves to a non-public IP",
      );

      // Comprueba que nunca se inició la conexión HTTPS.
      expect(requestSpy).not.toHaveBeenCalled();
    } finally {
      lookupSpy.mockRestore();
      requestSpy.mockRestore();
    }
  });

  test("secureFetch debe rechazar respuestas HTTP de redirección", async () => {
    const lookupSpy = jest.spyOn(dns, "lookup").mockResolvedValue([
      {
        address: "8.8.8.8",
        family: 4,
      },
    ]);

    const response = new EventEmitter();
    response.statusCode = 302;
    response.destroy = jest.fn();

    const request = new EventEmitter();
    request.setTimeout = jest.fn();
    request.end = jest.fn(() => {
      process.nextTick(() => {
        request.callback(response);
      });
    });

    const requestSpy = jest
      .spyOn(https, "request")
      .mockImplementation((options, callback) => {
        request.callback = callback;
        return request;
      });

    try {
      await expect(secureFetch("https://api.example.com")).rejects.toThrow(
        "Redirects are not allowed",
      );

      expect(requestSpy).toHaveBeenCalledTimes(1);
      expect(response.destroy).toHaveBeenCalledTimes(1);
    } finally {
      lookupSpy.mockRestore();
      requestSpy.mockRestore();
    }
  });

  test("demuestra que la función vulnerable permite acceder a un destino local", async () => {
    const response = await vulnerableFetch(serverUrl);

    expect(response.statusCode).toBe(200);
    expect(response.body).toContain("Contenido ficticio");
  });

  test("debe rechazar el protocolo HTTP", () => {
    expect(() => {
      validateDestination("http://api.example.com");
    }).toThrow("Only HTTPS destinations are allowed");
  });

  test("debe rechazar localhost", () => {
    expect(() => {
      validateDestination("https://localhost");
    }).toThrow("Destination host is not allowed");
  });

  test("debe rechazar direcciones IPv4 privadas", () => {
    expect(() => {
      validateDestination("https://192.168.1.10");
    }).toThrow("Destination host is not allowed");
  });

  test("debe rechazar dominios no autorizados", () => {
    expect(() => {
      validateDestination("https://attacker.example.com");
    }).toThrow("Destination host is not allowed");
  });

  test("debe rechazar credenciales incluidas en la URL", () => {
    expect(() => {
      validateDestination("https://user:password@api.example.com");
    }).toThrow("URL credentials are not allowed");
  });

  test("debe rechazar puertos diferentes al 443", () => {
    expect(() => {
      validateDestination("https://api.example.com:8443");
    }).toThrow("Destination port is not allowed");
  });

  test("debe rechazar direcciones IPv4 de CGNAT", () => {
    expect(isPublicIp("100.64.0.1")).toBe(false);
  });

  test("debe rechazar direcciones IPv4 multicast", () => {
    expect(isPublicIp("224.0.0.1")).toBe(false);
  });

  test("debe rechazar la dirección IPv4 no especificada", () => {
    expect(isPublicIp("0.0.0.0")).toBe(false);
  });

  test("debe rechazar direcciones IPv4 mapeadas en IPv6 que sean privadas", () => {
    expect(isPublicIp("::ffff:127.0.0.1")).toBe(false);
  });

  test("debe rechazar direcciones IPv6 reservadas para documentación", () => {
    expect(isPublicIp("2001:db8::1")).toBe(false);
  });
});
