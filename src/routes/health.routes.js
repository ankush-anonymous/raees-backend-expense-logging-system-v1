import { Router } from "express";
import * as healthController from "../controllers/health.controller.js";

const router = Router();

router.get("/", healthController.root);
router.get("/health", healthController.health);

export default router;
