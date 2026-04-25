import { Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import {
  authorizationCodeGrant,
  buildAuthorizationUrl,
  calculatePKCECodeChallenge,
  randomNonce,
  randomPKCECodeVerifier,
  randomState,
} from 'openid-client';
import type { Env } from '../../../config/env.schema';
import { PrismaService } from '../../../prisma/prisma.service';
import { TokenCryptoService } from '../../../crypto/token-crypto.service';
import { AuditService } from '../audit/audit.service';
import type { AuthProvider, AuthenticatedUser } from './auth.types';
import { discoverAzureAdConfiguration } from './providers/azuread.oidc';

type LoginInit = {
  url: string;
  state: string;
  nonce: string;
  codeVerifier: string;
};

@Injectable()
export class AuthService {
  private azureConfigPromise: ReturnType<typeof discoverAzureAdConfiguration> | null = null;

  constructor(
    private readonly config: ConfigService<Env, true>,
    private readonly prisma: PrismaService,
    private readonly crypto: TokenCryptoService,
    private readonly audit: AuditService,
  ) {}

  private async getAzureConfig() {
    if (!this.azureConfigPromise) {
      const tenantId = this.config.get('AZUREAD_TENANT_ID', { infer: true });
      const clientId = this.config.get('AZUREAD_CLIENT_ID', { infer: true });
      const clientSecret = this.config.get('AZUREAD_CLIENT_SECRET', { infer: true });
      this.azureConfigPromise = discoverAzureAdConfiguration(tenantId, clientId, clientSecret);
    }
    return this.azureConfigPromise;
  }

  async beginLogin(provider: AuthProvider): Promise<LoginInit> {
    if (provider !== 'azuread') throw new UnauthorizedException('Provider not enabled.');

    // PKCE + state + nonce even though we are server-side (defense-in-depth, aligns with SPA expectations).
    const state = randomState();
    const nonce = randomNonce();
    const codeVerifier = randomPKCECodeVerifier();
    const codeChallenge = await calculatePKCECodeChallenge(codeVerifier);

    const scopes = this.config.get('AZUREAD_SCOPES', { infer: true }).split(/\s+/).filter(Boolean);
    const cfg = await this.getAzureConfig();
    const redirectUri = this.config.get('AZUREAD_REDIRECT_URI', { infer: true });
    const url = buildAuthorizationUrl(cfg, {
      redirect_uri: redirectUri,
      scope: scopes.join(' '),
      state,
      nonce,
      code_challenge: codeChallenge,
      code_challenge_method: 'S256',
    });

    return { url: url.toString(), state, nonce, codeVerifier };
  }

  async handleAzureCallback(args: {
    code: string;
    state: string;
    expectedState: string;
    expectedNonce: string;
    codeVerifier: string;
    ip?: string;
    userAgent?: string;
  }): Promise<{ sessionId: string; user: AuthenticatedUser }> {
    if (args.state !== args.expectedState) throw new UnauthorizedException('Invalid OAuth state.');

    const cfg = await this.getAzureConfig();
    const redirectUri = this.config.get('AZUREAD_REDIRECT_URI', { infer: true });

    const callbackUrl = new URL(redirectUri);
    callbackUrl.searchParams.set('code', args.code);
    callbackUrl.searchParams.set('state', args.state);

    const tokens = await authorizationCodeGrant(cfg, callbackUrl, {
      pkceCodeVerifier: args.codeVerifier,
      expectedState: args.expectedState,
      expectedNonce: args.expectedNonce,
    });

    const claims = tokens.claims();
    if (!claims) throw new UnauthorizedException('Missing ID token claims.');
    const externalId = (claims.oid as string | undefined) ?? (claims.sub as string | undefined);
    if (!externalId) throw new UnauthorizedException('Missing user identifier from IdP.');

    const email = (claims.preferred_username as string | undefined) ?? (claims.email as string | undefined);
    const displayName = (claims.name as string | undefined) ?? undefined;
    const upn = (claims.upn as string | undefined) ?? undefined;

    // Azure AD group claims can be configured; if not present, this will be empty.
    const groups = Array.isArray((claims as any).groups) ? ((claims as any).groups as string[]) : [];

    const user = await this.prisma.user.upsert({
      where: { externalId },
      update: {
        provider: 'azuread',
        email,
        displayName,
        upn,
        groups,
      },
      create: {
        externalId,
        provider: 'azuread',
        email,
        displayName,
        upn,
        groups,
      },
    });

    // Resolve app roles from group mapping + overrides.
    const roleKeys = await this.resolveRolesForUser({
      userId: user.id,
      provider: 'azuread',
      tenantId: claims.tid as string | undefined,
      groups,
    });

    const ttlSeconds = this.config.get('SESSION_TTL_SECONDS', { infer: true });
    const expiresAt = new Date(Date.now() + ttlSeconds * 1000);

    const session = await this.prisma.session.create({
      data: {
        userId: user.id,
        expiresAt,
        lastSeenAt: new Date(),
        idTokenEnc: tokens.id_token ? this.crypto.encrypt(tokens.id_token) : undefined,
        accessTokenEnc: tokens.access_token ? this.crypto.encrypt(tokens.access_token) : undefined,
        refreshTokenEnc: tokens.refresh_token ? this.crypto.encrypt(tokens.refresh_token) : undefined,
        ip: args.ip,
        userAgent: args.userAgent,
      },
    });

    await this.audit.write({
      actorUserId: user.id,
      actorEmail: user.email ?? undefined,
      action: 'auth.login.success',
      outcome: 'success',
      ip: args.ip,
      userAgent: args.userAgent,
      meta: { provider: 'azuread' },
    });

    return {
      sessionId: session.id,
      user: {
        userId: user.id,
        provider: 'azuread',
        externalId: user.externalId,
        email: user.email ?? undefined,
        displayName: user.displayName ?? undefined,
        roles: roleKeys,
      },
    };
  }

  async logout(sessionId: string, ip?: string, userAgent?: string) {
    const session = await this.prisma.session.update({
      where: { id: sessionId },
      data: { revokedAt: new Date() },
      include: { user: true },
    });

    await this.audit.write({
      actorUserId: session.userId,
      actorEmail: session.user.email ?? undefined,
      action: 'auth.logout',
      outcome: 'success',
      ip,
      userAgent,
    });
  }

  async getMe(sessionId: string): Promise<AuthenticatedUser> {
    const session = await this.prisma.session.findFirst({
      where: { id: sessionId, revokedAt: null, expiresAt: { gt: new Date() } },
      include: { user: true },
    });
    if (!session) throw new UnauthorizedException('Invalid session.');

    await this.prisma.session.update({ where: { id: session.id }, data: { lastSeenAt: new Date() } });

    const roleKeys = await this.resolveRolesForUser({
      userId: session.userId,
      provider: session.user.provider as AuthProvider,
      tenantId: session.user.tenantId ?? undefined,
      groups: session.user.groups,
    });

    return {
      userId: session.userId,
      provider: session.user.provider as AuthProvider,
      externalId: session.user.externalId,
      email: session.user.email ?? undefined,
      displayName: session.user.displayName ?? undefined,
      roles: roleKeys,
    };
  }

  private async resolveRolesForUser(args: {
    userId: string;
    provider: AuthProvider;
    tenantId?: string;
    groups: string[];
  }): Promise<string[]> {
    const groupRoleMaps = args.groups.length
      ? await this.prisma.groupRoleMapping.findMany({
          where: {
            provider: args.provider,
            tenantId: args.tenantId ?? null,
            groupId: { in: args.groups },
          },
          include: { role: true },
        })
      : [];

    const overrides = await this.prisma.userRoleBinding.findMany({
      where: { userId: args.userId },
      include: { role: true },
    });

    const roles = new Set<string>();
    for (const m of groupRoleMaps) roles.add(m.role.key);
    for (const b of overrides) roles.add(b.role.key);

    if (roles.size === 0) roles.add('User'); // safe default
    return [...roles].sort();
  }
}

