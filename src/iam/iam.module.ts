import { Module } from '@nestjs/common';
import { AuthModule } from './modules/auth/auth.module';
import { AuditModule } from './modules/audit/audit.module';

@Module({
  imports: [AuthModule, AuditModule],
})
export class IamModule {}

