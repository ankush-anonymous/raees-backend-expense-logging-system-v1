import { HttpError } from "../utils/httpError.js";

export function requireAdmin(req, _res, next) {
  if (req.auth?.access !== "admin") {
    next(new HttpError(403, "Administrator access required."));
    return;
  }
  next();
}
