const jwt = require("jsonwebtoken");

const { JWT_SECRET, JWT_ISSUER, JWT_AUDIENCE } = require("../config/auth");

function authenticateToken(req, res, next) {
  const authorization = req.headers.authorization;

  if (typeof authorization !== "string") {
    return res.status(401).json({
      error: "Authentication required",
    });
  }

  const match = authorization.match(/^Bearer\s+(\S+)$/i);

  if (!match) {
    return res.status(401).json({
      error: "Invalid authorization format",
    });
  }

  try {
    const payload = jwt.verify(match[1], JWT_SECRET, {
      algorithms: ["HS256"],
      issuer: JWT_ISSUER,
      audience: JWT_AUDIENCE,
    });

    const userId = Number(payload.sub);

    if (
      !Number.isSafeInteger(userId) ||
      userId <= 0 ||
      typeof payload.email !== "string" ||
      !["admin", "user"].includes(payload.role)
    ) {
      return res.status(401).json({
        error: "Invalid authentication token",
      });
    }

    req.user = {
      id: userId,
      email: payload.email,
      role: payload.role,
    };

    return next();
  } catch (error) {
    return res.status(401).json({
      error: "Invalid or expired token",
    });
  }
}

function authorizeRoles(...allowedRoles) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        error: "Authentication required",
      });
    }

    if (!allowedRoles.includes(req.user.role)) {
      return res.status(403).json({
        error: "Insufficient permissions",
      });
    }

    return next();
  };
}

module.exports = {
  authenticateToken,
  authorizeRoles,
};
