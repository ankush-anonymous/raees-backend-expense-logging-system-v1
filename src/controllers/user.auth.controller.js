import crypto from "crypto";
import jwt from "jsonwebtoken";
import { User } from "../models/user.model.js";
import {
  sendLoginOtpEmail,
  sendRegistrationOtpEmail,
} from "../services/email.service.js";
import { signTokens, verifyRefreshToken } from "../utils/jwt.util.js";
import { HttpError } from "../utils/httpError.js";
import { generateOtp, hashOtp, otpMatches } from "../utils/otp.util.js";

/** @param {unknown} email */
function isNonEmptyEmail(email) {
  return (
    typeof email === "string" && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim())
  );
}

function otpExpiryDate() {
  const minutes = Number(process.env.OTP_EXPIRES_MINUTES);
  const m = Number.isFinite(minutes) && minutes > 0 ? minutes : 10;
  return new Date(Date.now() + m * 60 * 1000);
}

/** @param {string} provided @param {string} configured */
function secretsMatchConstantTime(provided, configured) {
  const a = Buffer.from(provided, "utf8");
  const b = Buffer.from(configured, "utf8");
  if (a.length !== b.length) {
    return false;
  }
  return crypto.timingSafeEqual(a, b);
}

/**
 * One-off / ops: creates a verified admin (no registration OTP).
 * Requires `ADMIN_BOOTSTRAP_SECRET` set in env and matching `bootstrapSecret` in JSON body.
 * Then sign in with POST /api/auth/login → verify OTP (same flow as existing users).
 */
export async function bootstrapAdmin(req, res, next) {
  try {
    const configuredSecret = process.env.ADMIN_BOOTSTRAP_SECRET?.trim();
    if (!configuredSecret) {
      throw new HttpError(
        503,
        "Admin bootstrap is not enabled (set ADMIN_BOOTSTRAP_SECRET).",
      );
    }

    const { name, email, bootstrapSecret } = req.body ?? {};
    if (typeof bootstrapSecret !== "string" || !bootstrapSecret) {
      throw new HttpError(400, "bootstrapSecret is required.");
    }

    if (!secretsMatchConstantTime(bootstrapSecret, configuredSecret)) {
      throw new HttpError(403, "Invalid bootstrap credential.");
    }

    if (typeof name !== "string" || !name.trim()) {
      throw new HttpError(400, "Name is required.");
    }
    if (!isNonEmptyEmail(email)) {
      throw new HttpError(400, "A valid email is required.");
    }

    const trimmedName = name.trim();
    const normalizedEmail = email.trim().toLowerCase();

    const existing = await User.findOne({ email: normalizedEmail });
    if (existing) {
      throw new HttpError(409, "An account already exists with this email.");
    }

    await User.create({
      name: trimmedName,
      email: normalizedEmail,
      access: "admin",
      isEmailVerified: true,
    });

    res.status(201).json({
      message:
        "Admin created. Sign in with POST /api/auth/login (OTP emailed), then verify OTP for tokens.",
      email: normalizedEmail,
    });
  } catch (err) {
    next(err);
  }
}

export async function register(req, res, next) {
  try {
    const { name, email } = req.body ?? {};

    if (typeof name !== "string" || !name.trim()) {
      throw new HttpError(400, "Name is required.");
    }
    if (!isNonEmptyEmail(email)) {
      throw new HttpError(400, "A valid email is required.");
    }

    const trimmedName = name.trim();
    const normalizedEmail = email.trim().toLowerCase();

    const existingVerified = await User.findOne({
      email: normalizedEmail,
      isEmailVerified: true,
    });
    if (existingVerified) {
      throw new HttpError(409, "This email is already registered.");
    }

    const otp = generateOtp();
    const otpHash = hashOtp(otp);
    const otpExpiresAt = otpExpiryDate();

    let doc = await User.findOne({ email: normalizedEmail });
    if (doc) {
      doc.name = trimmedName;
      doc.otpHash = otpHash;
      doc.otpExpiresAt = otpExpiresAt;
      await doc.save();
    } else {
      doc = await User.create({
        name: trimmedName,
        email: normalizedEmail,
        otpHash,
        otpExpiresAt,
        isEmailVerified: false,
      });
    }

    await sendRegistrationOtpEmail(normalizedEmail, trimmedName, otp);

    res.status(201).json({
      message: "Verification code sent to your email.",
      email: normalizedEmail,
    });
  } catch (err) {
    next(err);
  }
}

/**
 * Sends sign-in OTP for verified accounts only. Others get explicit prompts to register or finish verification.
 * Reuse POST /auth/verify-otp with email + otp to get JWTs after login.
 */
export async function login(req, res, next) {
  try {
    const { email } = req.body ?? {};

    if (!isNonEmptyEmail(email)) {
      throw new HttpError(400, "A valid email is required.");
    }
    const normalizedEmail = email.trim().toLowerCase();

    const userVerified = await User.findOne({
      email: normalizedEmail,
      isEmailVerified: true,
    });

    if (userVerified) {
      const otp = generateOtp();
      userVerified.otpHash = hashOtp(otp);
      userVerified.otpExpiresAt = otpExpiryDate();
      await userVerified.save();
      await sendLoginOtpEmail(normalizedEmail, userVerified.name, otp);

      return res.status(200).json({
        message:
          "Account found. Enter the sign-in code sent to your registered email address.",
        email: normalizedEmail,
      });
    }

    const pending = await User.findOne({
      email: normalizedEmail,
      isEmailVerified: false,
    });
    if (pending) {
      return res.status(400).json({
        message:
          "This email is not verified yet. Please complete registration first.",
      });
    }

    return res.status(404).json({
      message:
        "This email is not registered. Please register to create an account.",
    });
  } catch (err) {
    next(err);
  }
}

export async function verifyOtpAndIssueTokens(req, res, next) {
  try {
    const { email, otp } = req.body ?? {};

    if (!isNonEmptyEmail(email)) {
      throw new HttpError(400, "A valid email is required.");
    }
    const normalizedEmail = email.trim().toLowerCase();

    const user = await User.findOne({ email: normalizedEmail }).select(
      "+otpHash",
    );
    if (!user) {
      throw new HttpError(400, "Invalid or expired code.");
    }

    if (user.isEmailVerified && !user.otpHash) {
      throw new HttpError(
        400,
        "No active code for this email. Register, sign in first to receive a code, or wait for a new one.",
      );
    }

    if (
      !user.otpHash ||
      !user.otpExpiresAt ||
      user.otpExpiresAt.getTime() < Date.now()
    ) {
      throw new HttpError(400, "Invalid or expired code.");
    }

    if (!otpMatches(String(otp ?? ""), user.otpHash)) {
      throw new HttpError(401, "Invalid or expired code.");
    }

    const updated = await User.findByIdAndUpdate(
      user._id,
      {
        $set: { isEmailVerified: true },
        $unset: { otpHash: 1, otpExpiresAt: 1 },
      },
      { new: true },
    );
    if (!updated) {
      throw new HttpError(500, "Failed to complete verification.");
    }

    const { accessToken, refreshToken } = signTokens(updated);

    res.status(200).json({
      accessToken,
      refreshToken,
      user: {
        id: updated._id,
        name: updated.name,
        email: updated.email,
        access: updated.access,
      },
    });
  } catch (err) {
    next(err);
  }
}

/** Body: `{ refreshToken }` — verifies refresh JWT (`exp` enforced) and returns a new access + refresh pair (rotation). */
export async function refreshTokens(req, res, next) {
  try {
    const { refreshToken } = req.body ?? {};
    if (typeof refreshToken !== "string" || !refreshToken.trim()) {
      throw new HttpError(400, "Refresh token is required.");
    }

    let decoded;
    try {
      decoded = verifyRefreshToken(refreshToken.trim());
    } catch (err) {
      if (err instanceof jwt.TokenExpiredError) {
        throw new HttpError(
          401,
          "Refresh token expired. Please sign in again.",
        );
      }
      if (err instanceof jwt.NotBeforeError) {
        throw new HttpError(401, "Refresh token not active yet.");
      }
      if (err instanceof jwt.JsonWebTokenError) {
        throw new HttpError(401, "Invalid refresh token.");
      }
      throw err;
    }

    if (!decoded.sub) {
      throw new HttpError(401, "Invalid refresh token.");
    }

    const user = await User.findById(decoded.sub);
    if (!user?.isEmailVerified) {
      throw new HttpError(401, "Invalid refresh token.");
    }

    const { accessToken, refreshToken: nextRefreshToken } =
      signTokens(user);

    res.status(200).json({
      accessToken,
      refreshToken: nextRefreshToken,
    });
  } catch (err) {
    next(err);
  }
}
