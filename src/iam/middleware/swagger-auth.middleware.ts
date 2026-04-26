import { Injectable } from '@nestjs/common';
import type { NextFunction, Request, Response } from 'express';
import { ConfigService } from '@nestjs/config';
import type { Env } from '../../config/env.schema';
import { AuthService } from '../modules/auth/auth.service';
import { AzureAdJwtService } from '../modules/jwt/azuread-jwt.service';

@Injectable()
export class SwaggerAuthMiddleware {
  constructor(
    private readonly config: ConfigService<Env, true>,
    private readonly auth: AuthService,
    private readonly azureJwt: AzureAdJwtService,
  ) {}

  async use(req: Request, res: Response, next: NextFunction) {
    const nodeEnv = this.config.get('NODE_ENV', { infer: true });
    const enableSwagger = this.config.get('ENABLE_SWAGGER', { infer: true });
    if (!(enableSwagger && nodeEnv === 'development')) return res.status(404).send('Not found.');

    // Accept either:
    // - session cookie (browser dev usage)
    // - bearer JWT (API client usage; full JWT validation is added separately)
    const cookieName = this.config.get('SESSION_COOKIE_NAME', { infer: true });
    const sessionId = (req.cookies?.[cookieName] as string | undefined) ?? undefined;
    const authz = req.get('authorization') ?? '';
    const hasBearer = authz.toLowerCase().startsWith('bearer ');

    if (sessionId) {
      try {
        await this.auth.getMe(sessionId);
        return next();
      } catch {
        return res.status(401).send('Unauthorized');
      }
    }

    if (hasBearer) {
      const token = authz.slice('bearer '.length).trim();
      try {
        await this.azureJwt.verifyBearerToken(token);
        return next();
      } catch {
        return res.status(401).send('Unauthorized');
      }
    }

    return res.status(401).send('Unauthorized');
  }
}

