import { Module } from '@nestjs/common';
import { AzureAdJwtService } from './azuread-jwt.service';
import { JwtAuthGuard } from './jwt-auth.guard';

@Module({
  providers: [AzureAdJwtService, JwtAuthGuard],
  exports: [AzureAdJwtService, JwtAuthGuard],
})
export class JwtModule {}

