import mongoose from "mongoose";
import { User } from "../models/user.model.js";
import { HttpError } from "../utils/httpError.js";

const USER_SNAPSHOT_SELECT =
  "_id name email access isEmailVerified createdAt updatedAt";

/** @param {string | undefined} access */
function refuseAdminDeletion(access) {
  if (access === "admin") {
    throw new HttpError(
      403,
      "Administrator accounts cannot be deleted through the API.",
    );
  }
}

/** GET /users/me — authenticated user profile */
export async function getOwnProfile(req, res, next) {
  try {
    const user = await User.findById(req.auth.userId)
      .select("_id name email access isEmailVerified createdAt updatedAt")
      .lean();

    if (!user) {
      throw new HttpError(404, "User not found.");
    }

    res.status(200).json({ user: User.toSafeLean(user) });
  } catch (err) {
    next(err);
  }
}

/** GET /users — admins only; active users only */
export async function listUsers(_req, res, next) {
  try {
    const users = await User.find()
      .sort({ createdAt: -1 })
      .select("_id name email access isEmailVerified createdAt updatedAt")
      .lean()
      .exec();

    res.status(200).json({
      users: users.map((u) => User.toSafeLean(u)),
    });
  } catch (err) {
    next(err);
  }
}

/** GET /users/:userId — yourself or admin */
export async function getUserById(req, res, next) {
  try {
    const { userId } = req.params;

    if (!mongoose.isValidObjectId(userId)) {
      throw new HttpError(400, "Invalid user id.");
    }

    const self = req.auth.userId === userId;
    const isAdmin = req.auth.access === "admin";
    if (!self && !isAdmin) {
      throw new HttpError(
        403,
        "You may only view your own profile unless you are an administrator.",
      );
    }

    const user = await User.findById(userId)
      .select("_id name email access isEmailVerified createdAt updatedAt")
      .lean();

    if (!user) {
      throw new HttpError(404, "User not found.");
    }

    res.status(200).json({ user: User.toSafeLean(user) });
  } catch (err) {
    next(err);
  }
}

/** DELETE /users/me — soft delete authenticated user */
export async function deleteOwnAccount(req, res, next) {
  try {
    const me = await User.findById(req.auth.userId)
      .select(USER_SNAPSHOT_SELECT)
      .lean();
    if (!me) {
      throw new HttpError(404, "User not found.");
    }
    refuseAdminDeletion(me.access);

    const modified = await User.softDeleteUserById(req.auth.userId);
    if (!modified) {
      throw new HttpError(404, "User not found.");
    }

    const id = String(me._id);
    res.status(200).json({
      message: `User ${id} was deleted (soft).`,
      user: User.toSafeLean(me),
    });
  } catch (err) {
    next(err);
  }
}

/**
 * DELETE /users/:userId — soft delete own account by id or any user when admin.
 */
export async function deleteUserById(req, res, next) {
  try {
    const { userId } = req.params;

    if (!mongoose.isValidObjectId(userId)) {
      throw new HttpError(400, "Invalid user id.");
    }

    const target = await User.findById(userId)
      .select(USER_SNAPSHOT_SELECT)
      .lean();
    if (!target) {
      throw new HttpError(404, "User not found.");
    }
    refuseAdminDeletion(target.access);

    const self = req.auth.userId === userId;
    const isAdmin = req.auth.access === "admin";
    if (!self && !isAdmin) {
      throw new HttpError(
        403,
        "You may only delete your own account unless you are an administrator.",
      );
    }

    const modified = await User.softDeleteUserById(userId);
    if (!modified) {
      throw new HttpError(404, "User not found.");
    }

    const id = String(target._id);
    res.status(200).json({
      message: `User ${id} was deleted (soft).`,
      user: User.toSafeLean(target),
    });
  } catch (err) {
    next(err);
  }
}
