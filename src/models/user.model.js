import mongoose from "mongoose";

export const ACCESS_LEVELS = ["user", "admin"];

const userSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: true,
      trim: true,
    },
    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
    },
    authToken: {
      type: String,
    },
    isEmailVerified: {
      type: Boolean,
      default: false,
    },
    /** HMAC digest of OTP; omit from defaults until register. */
    otpHash: {
      type: String,
      select: false,
    },
    otpExpiresAt: {
      type: Date,
    },
    access: {
      type: String,
      enum: ACCESS_LEVELS,
      default: "user",
      required: true,
    },
  },
  { timestamps: true }
);

export const User = mongoose.model("User", userSchema);
