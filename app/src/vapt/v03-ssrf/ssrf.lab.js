const http = require("node:http");
const https = require("node:https");
const dns = require("node:dns").promises;
const net = require("node:net");
const ipaddr = require("ipaddr.js");

function vulnerableFetch(url) {
  return new Promise((resolve, reject) => {
    const client = url.startsWith("https:") ? https : http;

    client
      .get(url, (response) => {
        let body = "";

        response.setEncoding("utf8");
        response.on("data", (chunk) => (body += chunk));

        response.on("end", () => {
          resolve({
            statusCode: response.statusCode,
            body,
          });
        });
      })
      .on("error", reject);
  });
}

const ALLOWED_HOSTS = new Set(["api.example.com"]);

const REQUEST_TIMEOUT_MS = 3000;
const MAX_RESPONSE_BYTES = 1024 * 1024;

function isPublicIp(address) {
  if (net.isIP(address) === 0) {
    return false;
  }

  let parsed;

  try {
    parsed = ipaddr.parse(address);
  } catch {
    return false;
  }

  if (parsed.kind() === "ipv6" && parsed.isIPv4MappedAddress()) {
    parsed = parsed.toIPv4Address();
  }

  // Solo se permiten direcciones clasificadas como unicast.
  // Se excluyen rangos privados, loopback, link-local,
  // multicast y rangos especiales reconocidos por ipaddr.js.
  return parsed.range() === "unicast";
}

function validateDestination(rawUrl) {
  let destination;

  try {
    destination = new URL(rawUrl);
  } catch {
    throw new Error("Invalid URL");
  }

  if (destination.protocol !== "https:") {
    throw new Error("Only HTTPS destinations are allowed");
  }

  if (destination.username || destination.password) {
    throw new Error("URL credentials are not allowed");
  }

  if (destination.port && destination.port !== "443") {
    throw new Error("Destination port is not allowed");
  }

  const hostname = destination.hostname.toLowerCase();

  if (!ALLOWED_HOSTS.has(hostname)) {
    throw new Error("Destination host is not allowed");
  }

  if (net.isIP(hostname)) {
    throw new Error("IP literal destinations are not allowed");
  }

  return destination;
}

async function resolveAndValidateHost(hostname) {
  const addresses = await dns.lookup(hostname, {
    all: true,
    verbatim: true,
  });

  if (!addresses.length) {
    throw new Error("Destination host has no IP addresses");
  }

  if (addresses.some(({ address }) => !isPublicIp(address))) {
    throw new Error("Destination resolves to a non-public IP");
  }

  return addresses;
}

async function secureFetch(rawUrl) {
  const destination = validateDestination(rawUrl);

  // Resuelve una sola vez y valida todas las direcciones.
  const addresses = await resolveAndValidateHost(destination.hostname);

  const selectedAddress = addresses[0];

  return new Promise((resolve, reject) => {
    let settled = false;
    let responseBytes = 0;
    const chunks = [];

    const finishWithError = (error) => {
      if (settled) return;

      settled = true;
      clearTimeout(totalTimeout);
      reject(error);
    };

    const request = https.request(
      {
        protocol: "https:",
        hostname: destination.hostname,
        port: 443,
        path: `${destination.pathname}${destination.search}`,
        method: "GET",
        headers: {
          Host: destination.host,
        },
        rejectUnauthorized: true,
        servername: destination.hostname,

        // Evita una nueva resolución DNS no controlada.
        // Todas las direcciones entregadas a Node ya fueron
        // validadas antes de iniciar la conexión.
        lookup: (_hostname, options, callback) => {
          if (options && options.all) {
            callback(null, addresses);
          } else {
            callback(null, selectedAddress.address, selectedAddress.family);
          }
        },
      },
      (response) => {
        if (response.statusCode >= 300 && response.statusCode < 400) {
          response.destroy();

          finishWithError(new Error("Redirects are not allowed"));

          return;
        }

        response.on("data", (chunk) => {
          if (settled) return;

          responseBytes += chunk.length;

          if (responseBytes > MAX_RESPONSE_BYTES) {
            response.destroy();

            request.destroy(new Error("Response size limit exceeded"));

            finishWithError(new Error("Response size limit exceeded"));

            return;
          }

          chunks.push(chunk);
        });

        response.on("end", () => {
          if (settled) return;

          settled = true;
          clearTimeout(totalTimeout);

          resolve({
            statusCode: response.statusCode,
            body: Buffer.concat(chunks).toString("utf8"),
          });
        });

        response.on("error", finishWithError);
      },
    );

    // Límite total de duración de la solicitud.
    const totalTimeout = setTimeout(() => {
      request.destroy(new Error("Request timeout"));
    }, REQUEST_TIMEOUT_MS);

    request.on("error", finishWithError);

    request.end();
  });
}

module.exports = {
  vulnerableFetch,
  secureFetch,
  validateDestination,
  isPublicIp,
  resolveAndValidateHost,
};
