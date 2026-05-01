import jwt from "jsonwebtoken";
import { HttpError } from "../utils/httpError.js";
import { verifyAccessToken } from "../utils/jwt.util.js";

/**
 * Validates `Authorization: Bearer <accessToken>`.
 * JWT `exp` is enforced automatically by jsonwebtoken.
 * @typedef {{ userId: string; email: string; access: string }} ReqAuth */
export function requireAccessToken(req, res, next) {
  const header = req.headers.authorization;
  if (!header?.startsWith("Bearer ")) {
    next(
      new HttpError(
        401,
        "Authorization required. Send header: Authorization: Bearer <access_token>",
      ),
    );
    return;
  }

  const token = header.slice("Bearer ".length).trim();
  if (!token) {
    next(new HttpError(401, "Access token is missing."));
    return;
  }

  try {
    const payload = verifyAccessToken(token);
    req.auth = {
      userId: payload.sub,
      email: payload.email,
      access: payload.access,
    };
    next();
  } catch (err) {
    if (err instanceof jwt.TokenExpiredError) {
      next(
        new HttpError(
          401,
          "Access token expired. Sign in again to receive a new one.",
        ),
      );
      return;
    }
    if (err instanceof jwt.NotBeforeError) {
      next(new HttpError(401, "Access token not active yet."));
      return;
    }
    if (err instanceof jwt.JsonWebTokenError) {
      next(new HttpError(401, "Invalid access token."));
      return;
    }
    next(err);
  }
}
