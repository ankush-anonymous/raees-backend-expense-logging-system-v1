import { User } from "../models/user.model.js";
import { sendRegistrationOtpEmail } from "../services/email.service.js";
import { signTokens } from "../utils/jwt.util.js";
import { generateOtp, hashOtp, otpMatches } from "../utils/otp.util.js";

class HttpError extends Error {
  /**
   * @param {number} statusCode
   * @param {string} message
   */
  constructor(statusCode, message) {
    super(message);
    this.statusCode = statusCode;
  }
}

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
        "This email is already verified. Sign in instead.",
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
