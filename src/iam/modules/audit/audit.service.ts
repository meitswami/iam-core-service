import { Injectable } from '@nestjs/common';
import { PrismaService } from '../../../prisma/prisma.service';
import { Prisma } from '@prisma/client';

type AuditOutcome = 'success' | 'failure';

@Injectable()
export class AuditService {
  constructor(private readonly prisma: PrismaService) {}

  async write(entry: {
    actorUserId?: string;
    actorEmail?: string;
    action: string;
    outcome: AuditOutcome;
    ip?: string;
    userAgent?: string;
    target?: string;
    meta?: Record<string, unknown>;
  }) {
    await this.prisma.auditLog.create({
      data: {
        actorUserId: entry.actorUserId,
        actorEmail: entry.actorEmail,
        action: entry.action,
        outcome: entry.outcome,
        ip: entry.ip,
        userAgent: entry.userAgent,
        target: entry.target,
        meta: (entry.meta ?? undefined) as Prisma.InputJsonValue | undefined,
      },
    });
  }
}

