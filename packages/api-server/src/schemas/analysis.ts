import { z } from 'zod';

export const transactionAnalysisSchema = z.object({
  signature: z.string().min(1, 'Signature is required'),
  network: z.enum(['mainnet-beta', 'devnet', 'testnet']).optional(),
});

export const addressAnalysisSchema = z.object({
  address: z.string().min(1, 'Address is required'),
  network: z.enum(['mainnet-beta', 'devnet', 'testnet']).optional(),
  depth: z.number().min(1).max(100).optional(),
});

