import { Router } from "express";
import authRoutes from "./user.auth.routes.js";
import healthRoutes from "./health.routes.js";
import userRoutes from "./user.routes.js";

const router = Router();

router.use(healthRoutes);
router.use(authRoutes);
router.use(userRoutes);

export default router;
