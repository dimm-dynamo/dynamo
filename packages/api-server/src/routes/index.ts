import { Router } from 'express';
import analyzeRoutes from './analyze';
import auditRoutes from './audit';
import monitorRoutes from './monitor';

const router = Router();

router.use('/analyze', analyzeRoutes);
router.use('/audit', auditRoutes);
router.use('/monitor', monitorRoutes);

export default router;

