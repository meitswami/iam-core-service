import { CanActivate, ExecutionContext, Injectable } from '@nestjs/common';
import type { Request } from 'express';
import { ConfigService } from '@nestjs/config';
import type { Env } from '../../config/env.schema';
import { AuthService } from '../modules/auth/auth.service';
import type { AuthenticatedUser } from '../modules/auth/auth.types';

declare module 'express-serve-static-core' {
  interface Request {
    iamUser?: AuthenticatedUser;
  }
}

@Injectable()
export class SessionAuthGuard implements CanActivate {
  constructor(
    private readonly config: ConfigService<Env, true>,
    private readonly auth: AuthService,
  ) {}

  async canActivate(ctx: ExecutionContext): Promise<boolean> {
    const req = ctx.switchToHttp().getRequest<Request>();
    const cookieName = this.config.get('SESSION_COOKIE_NAME', { infer: true });
    const sessionId = (req.cookies?.[cookieName] as string | undefined) ?? undefined;
    if (!sessionId) return false;

    const user = await this.auth.getMe(sessionId);
    req.iamUser = user;
    return true;
  }
}

