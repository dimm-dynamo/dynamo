import { Router } from 'express';
import { analyzeTransaction, analyzeAddress } from '../controllers/analyzeController';
import { validateRequest } from '../middleware/validation';
import { transactionAnalysisSchema, addressAnalysisSchema } from '../schemas/analysis';

const router = Router();

router.post('/transaction', validateRequest(transactionAnalysisSchema), analyzeTransaction);
router.post('/address', validateRequest(addressAnalysisSchema), analyzeAddress);

export default router;

