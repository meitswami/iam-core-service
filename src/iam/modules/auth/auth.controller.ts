import { Controller, Get, Post, Query, Req, Res, UseGuards } from '@nestjs/common';
import { ThrottlerGuard, Throttle } from '@nestjs/throttler';
import type { Request, Response } from 'express';
import { ConfigService } from '@nestjs/config';
import type { Env } from '../../../config/env.schema';
import { AuthService } from './auth.service';
import type { AuthProvider } from './auth.types';

function getIp(req: Request): string | undefined {
  // If running behind a trusted proxy, set app.set('trust proxy', 1) in main.ts.
  return req.ip;
}

@Controller('auth')
@UseGuards(ThrottlerGuard)
export class AuthController {
  constructor(
    private readonly auth: AuthService,
    private readonly config: ConfigService<Env, true>,
  ) {}

  private cookieSecure(): boolean {
    const env = this.config.get('NODE_ENV', { infer: true });
    return this.config.get('COOKIE_SECURE', { infer: true }) ?? env === 'production';
  }

  @Get('login')
  @Throttle({ default: { limit: 10, ttl: 60_000 } })
  async login(@Res() res: Response, @Query('provider') provider?: AuthProvider) {
    const init = await this.auth.beginLogin(provider ?? 'azuread');

    // Store transient PKCE material in HttpOnly cookies to avoid any JS access.
    // These are short-lived and scoped to auth flow only.
    const secure = this.cookieSecure();
    res.cookie('__Host-oidc_state', init.state, { httpOnly: true, secure, sameSite: 'lax', path: '/auth' });
    res.cookie('__Host-oidc_nonce', init.nonce, { httpOnly: true, secure, sameSite: 'lax', path: '/auth' });
    res.cookie('__Host-oidc_cv', init.codeVerifier, { httpOnly: true, secure, sameSite: 'lax', path: '/auth' });

    return res.redirect(302, init.url);
  }

  @Get('callback')
  @Throttle({ default: { limit: 20, ttl: 60_000 } })
  async callback(
    @Req() req: Request,
    @Res() res: Response,
    @Query('code') code?: string,
    @Query('state') state?: string,
    @Query('provider') provider?: AuthProvider,
  ) {
    if (!code || !state) return res.status(400).send('Missing code/state.');

    const expectedState = req.cookies?.['__Host-oidc_state'] as string | undefined;
    const expectedNonce = req.cookies?.['__Host-oidc_nonce'] as string | undefined;
    const codeVerifier = req.cookies?.['__Host-oidc_cv'] as string | undefined;
    if (!expectedState || !expectedNonce || !codeVerifier) return res.status(400).send('Missing login state.');

    // Clear transient cookies regardless of success.
    res.clearCookie('__Host-oidc_state', { path: '/auth' });
    res.clearCookie('__Host-oidc_nonce', { path: '/auth' });
    res.clearCookie('__Host-oidc_cv', { path: '/auth' });

    const { sessionId } = await this.auth.handleCallback({
      provider: provider ?? 'azuread',
      code,
      state,
      expectedState,
      expectedNonce,
      codeVerifier,
      ip: getIp(req),
      userAgent: req.get('user-agent') ?? undefined,
      requestId: (req as any).requestId as string | undefined,
    });

    const cookieName = this.config.get('SESSION_COOKIE_NAME', { infer: true });
    const ttlSeconds = this.config.get('SESSION_TTL_SECONDS', { infer: true });
    const cookieDomain = this.config.get('COOKIE_DOMAIN', { infer: true });
    const secure = this.cookieSecure();

    res.cookie(cookieName, sessionId, {
      httpOnly: true,
      secure,
      sameSite: 'lax',
      path: '/',
      domain: cookieDomain,
      maxAge: ttlSeconds * 1000,
    });

    // Redirect back to frontend app after login.
    const appUrl = this.config.get('APP_PUBLIC_URL', { infer: true });
    return res.redirect(302, `${appUrl}/auth/success`);
  }

  @Get('logout')
  async logout(@Req() req: Request, @Res() res: Response) {
    const cookieName = this.config.get('SESSION_COOKIE_NAME', { infer: true });
    const cookieDomain = this.config.get('COOKIE_DOMAIN', { infer: true });
    const sessionId = (req.cookies?.[cookieName] as string | undefined) ?? undefined;

    if (sessionId) await this.auth.logout(sessionId, getIp(req), req.get('user-agent') ?? undefined);

    res.clearCookie(cookieName, { path: '/', domain: cookieDomain });
    const appUrl = this.config.get('APP_PUBLIC_URL', { infer: true });
    return res.redirect(302, `${appUrl}/`);
  }

  @Get('me')
  async me(@Req() req: Request) {
    const cookieName = this.config.get('SESSION_COOKIE_NAME', { infer: true });
    const sessionId = (req.cookies?.[cookieName] as string | undefined) ?? undefined;
    if (!sessionId) return { authenticated: false };
    const user = await this.auth.getMe(sessionId);
    return { authenticated: true, user };
  }

  @Post('refresh')
  @Throttle({ default: { limit: 30, ttl: 60_000 } })
  async refresh(@Req() req: Request) {
    const cookieName = this.config.get('SESSION_COOKIE_NAME', { infer: true });
    const sessionId = (req.cookies?.[cookieName] as string | undefined) ?? undefined;
    if (!sessionId) return { ok: false };
    return await this.auth.refreshSession(sessionId, {
      ip: getIp(req),
      userAgent: req.get('user-agent') ?? undefined,
      requestId: (req as any).requestId as string | undefined,
    });
  }
}

