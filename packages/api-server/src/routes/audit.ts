import { Router } from 'express';
import { auditContract } from '../controllers/auditController';
import { validateRequest } from '../middleware/validation';
import { contractAuditSchema } from '../schemas/audit';

const router = Router();

router.post('/contract', validateRequest(contractAuditSchema), auditContract);

export default router;

