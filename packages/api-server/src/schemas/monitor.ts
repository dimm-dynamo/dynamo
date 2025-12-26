import { z } from 'zod';

export const monitorSchema = z.object({
  address: z.string().min(1, 'Address is required'),
  network: z.enum(['mainnet-beta', 'devnet', 'testnet']).optional(),
  webhookUrl: z.string().url().optional(),
});

