import { Router } from "express";
import * as authController from "../controllers/user.auth.controller.js";

const router = Router();

router.post("/auth/register", authController.register);
router.post("/auth/verify-otp", authController.verifyOtpAndIssueTokens);

export default router;
