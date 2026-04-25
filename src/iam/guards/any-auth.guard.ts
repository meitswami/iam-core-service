import { CanActivate, ExecutionContext, Injectable } from '@nestjs/common';
import { JwtAuthGuard } from '../modules/jwt/jwt-auth.guard';
import { SessionAuthGuard } from './session-auth.guard';

@Injectable()
export class AnyAuthGuard implements CanActivate {
  constructor(
    private readonly session: SessionAuthGuard,
    private readonly jwt: JwtAuthGuard,
  ) {}

  async canActivate(ctx: ExecutionContext): Promise<boolean> {
    // Prefer session cookie for browser usage, fallback to bearer JWT.
    if (await this.session.canActivate(ctx)) return true;
    return this.jwt.canActivate(ctx);
  }
}

