const JWT_SECRET = process.env.JWT_SECRET;

if (!JWT_SECRET || Buffer.byteLength(JWT_SECRET, "utf8") < 32) {
  throw new Error(
    "JWT_SECRET must be configured and contain at least 32 bytes",
  );
}

const JWT_ISSUER = "fleetsec-api";
const JWT_AUDIENCE = "fleetsec-client";
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || "15m";

module.exports = {
  JWT_SECRET,
  JWT_ISSUER,
  JWT_AUDIENCE,
  JWT_EXPIRES_IN,
};
