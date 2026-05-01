import { Router } from "express";
import * as authController from "../controllers/user.auth.controller.js";

const router = Router();

router.post("/auth/bootstrap-admin", authController.bootstrapAdmin);
router.post("/auth/register", authController.register);
router.post("/auth/login", authController.login);
router.post("/auth/verify-otp", authController.verifyOtpAndIssueTokens);
router.post("/auth/refresh", authController.refreshTokens);

export default router;
