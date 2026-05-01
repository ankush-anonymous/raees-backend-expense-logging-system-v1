import { Router } from "express";
import authRoutes from "./user.auth.routes.js";
import healthRoutes from "./health.routes.js";

const router = Router();

router.use(healthRoutes);
router.use(authRoutes);

export default router;
