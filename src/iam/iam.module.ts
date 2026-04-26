import { Module } from '@nestjs/common';
import { AuthModule } from './modules/auth/auth.module';
import { AuditModule } from './modules/audit/audit.module';
import { JwtModule } from './modules/jwt/jwt.module';
import { AnyAuthGuard } from './guards/any-auth.guard';
import { RolesGuard } from './guards/roles.guard';

@Module({
  imports: [AuthModule, AuditModule, JwtModule],
  providers: [AnyAuthGuard, RolesGuard],
  exports: [AnyAuthGuard, RolesGuard],
})
export class IamModule {}

