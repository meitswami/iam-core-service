import { CanActivate, ExecutionContext, Injectable } from '@nestjs/common';
import type { Request } from 'express';
import { AzureAdJwtService } from './azuread-jwt.service';

export type JwtAuthContext = {
  bearerClaims: unknown;
};

@Injectable()
export class JwtAuthGuard implements CanActivate {
  constructor(private readonly azureJwt: AzureAdJwtService) {}

  async canActivate(ctx: ExecutionContext): Promise<boolean> {
    const req = ctx.switchToHttp().getRequest<Request & { auth?: JwtAuthContext }>();
    const authz = req.get('authorization') ?? '';
    if (!authz.toLowerCase().startsWith('bearer ')) return false;

    const token = authz.slice('bearer '.length).trim();
    const { claims } = await this.azureJwt.verifyBearerToken(token);
    req.auth = { bearerClaims: claims };
    return true;
  }
}

