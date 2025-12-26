import { z } from 'zod';

export const contractAuditSchema = z.object({
  programId: z.string().min(1, 'Program ID is required'),
  network: z.enum(['mainnet-beta', 'devnet', 'testnet']).optional(),
  depth: z.enum(['shallow', 'deep']).optional(),
});

