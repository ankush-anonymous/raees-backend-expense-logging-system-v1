import { Router } from "express";
import * as userController from "../controllers/user.controller.js";
import { requireAccessToken } from "../middleware/requireAccessToken.middleware.js";
import { requireAdmin } from "../middleware/requireAdmin.middleware.js";

const router = Router();

router.get(
  "/users",
  requireAccessToken,
  requireAdmin,
  userController.listUsers,
);

router.get(
  "/users/me",
  requireAccessToken,
  userController.getOwnProfile,
);

router.get(
  "/users/:userId",
  requireAccessToken,
  userController.getUserById,
);

router.delete(
  "/users/me",
  requireAccessToken,
  userController.deleteOwnAccount,
);

router.delete(
  "/users/:userId",
  requireAccessToken,
  userController.deleteUserById,
);

export default router;
