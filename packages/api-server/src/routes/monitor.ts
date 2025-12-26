import { Router } from 'express';
import { monitorAddress, getMonitorStatus, stopMonitoring } from '../controllers/monitorController';
import { validateRequest } from '../middleware/validation';
import { monitorSchema } from '../schemas/monitor';

const router = Router();

router.post('/address', validateRequest(monitorSchema), monitorAddress);
router.get('/status/:monitorId', getMonitorStatus);
router.delete('/:monitorId', stopMonitoring);

export default router;

