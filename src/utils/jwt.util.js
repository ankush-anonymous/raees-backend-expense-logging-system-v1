import jwt from "jsonwebtoken";

function accessSecret() {
  const s = process.env.JWT_SECRET;
  if (!s) {
    throw new Error("JWT_SECRET is required.");
  }
  return s;
}

function refreshSecret() {
  const s = process.env.JWT_REFRESH_SECRET;
  if (!s) {
    throw new Error("JWT_REFRESH_SECRET is required.");
  }
  return s;
}

/**
 * Verifies access JWT (checks signature, `exp`, and issuer algorithm). Throws `jwt` errors subclasses for middleware to map.
 * @param {string} token Raw Bearer token (no prefix)
 */
export function verifyAccessToken(token) {
  return jwt.verify(token, accessSecret(), {
    algorithms: ["HS256"],
  });
}

/**
 * Verifies refresh JWT (`sub` + expiry). Throws `jwt.*` errors subclasses.
 * @param {string} token
 */
export function verifyRefreshToken(token) {
  return jwt.verify(token, refreshSecret(), {
    algorithms: ["HS256"],
  });
}

/** @param {import("mongoose").Document & { email: string; access: string }} user */
export function signTokens(user) {
  const userId = String(user._id);
  const accessPayload = {
    sub: userId,
    email: user.email,
    access: user.access,
  };

  const accessToken = jwt.sign(accessPayload, accessSecret(), {
    expiresIn: process.env.JWT_EXPIRES_IN ?? "15m",
    algorithm: "HS256",
  });

  const refreshToken = jwt.sign({ sub: userId }, refreshSecret(), {
    expiresIn: process.env.JWT_REFRESH_EXPIRES_IN ?? "7d",
    algorithm: "HS256",
  });

  return { accessToken, refreshToken };
}
