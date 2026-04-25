import { PrismaService } from '../../../prisma/prisma.service';
type AuditOutcome = 'success' | 'failure';
export declare class AuditService {
    private readonly prisma;
    constructor(prisma: PrismaService);
    write(entry: {
        actorUserId?: string;
        actorEmail?: string;
        action: string;
        outcome: AuditOutcome;
        ip?: string;
        userAgent?: string;
        target?: string;
        meta?: Record<string, unknown>;
    }): Promise<void>;
}
export {};
