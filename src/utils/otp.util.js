import crypto from "crypto";

/** @returns {string} */
function otpSecretMaterial() {
  const s = process.env.OTP_SECRET ?? process.env.JWT_SECRET;
  if (!s) {
    throw new Error("Set JWT_SECRET (or OTP_SECRET) for OTP signing.");
  }
  return s;
}

/** @returns {string} 6-digit OTP */
export function generateOtp() {
  return String(crypto.randomInt(0, 1_000_000)).padStart(6, "0");
}

/** @param {string} code */
export function hashOtp(code) {
  return crypto.createHmac("sha256", otpSecretMaterial()).update(String(code), "utf8").digest("hex");
}

/** @param {string} candidate @param {string} digestFromDb */
export function otpMatches(candidate, digestFromDb) {
  if (!candidate || !digestFromDb) {
    return false;
  }
  const hashed = Buffer.from(hashOtp(String(candidate)), "hex");
  const stored = Buffer.from(digestFromDb, "hex");
  if (hashed.length !== stored.length || stored.length === 0) {
    return false;
  }
  return crypto.timingSafeEqual(stored, hashed);
}
