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
    /** Set when soft-deleted; omitted from queries unless `{ withDeleted: true }`. */
    deletedAt: {
      type: Date,
      default: null,
      index: true,
    },
  },
  { timestamps: true }
);

/** Unique email among active (`deletedAt: null`) users only — new account can reuse email after soft delete. */
userSchema.index(
  { email: 1 },
  { unique: true, partialFilterExpression: { deletedAt: null } }
);

/** @param {mongoose.Schema} schema */
function applySoftDeleteQueryGuard(schema) {
  const ops = ["find", "findOne", "findOneAndUpdate", "countDocuments"];

  for (const op of ops) {
    schema.pre(op, function (next) {
      const opts = typeof this.getOptions === "function" ? this.getOptions() : {};
      if (opts.withDeleted === true) {
        next();
        return;
      }
      this.where({ deletedAt: null });
      next();
    });
  }
}

applySoftDeleteQueryGuard(userSchema);

/**
 * Soft-delete by Mongo id when the user exists and is not already deleted (`updateOne`; no reliance on filtered `find`).
 * @param {mongoose.Types.ObjectId | string} id
 * @returns {Promise<boolean>}
 */
userSchema.statics.softDeleteUserById = async function softDeleteUserById(id) {
  const result = await this.updateOne(
    { _id: id, deletedAt: null },
    { $set: { deletedAt: new Date() } },
  ).exec();
  return result.modifiedCount === 1;
};

/** @param {{ _id?: unknown }} leanOrDoc */
userSchema.statics.toSafeLean = function toSafeLean(leanOrDoc) {
  const o = leanOrDoc ?? {};
  return {
    id: String(o._id),
    name: o.name,
    email: o.email,
    access: o.access,
    isEmailVerified: o.isEmailVerified,
    createdAt: o.createdAt,
    updatedAt: o.updatedAt,
  };
};

export const User = mongoose.model("User", userSchema);
