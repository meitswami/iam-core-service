import { Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import type { Env } from '../../../config/env.schema';
import { createRemoteJWKSet, jwtVerify } from 'jose';
import { discoverAzureAdConfiguration } from '../auth/providers/azuread.oidc';

export type AzureAdJwtClaims = {
  sub?: string;
  oid?: string;
  tid?: string;
  upn?: string;
  name?: string;
  preferred_username?: string;
  email?: string;
  roles?: string[];
  groups?: string[];
};

@Injectable()
export class AzureAdJwtService {
  private jwksPromise: Promise<ReturnType<typeof createRemoteJWKSet>> | null = null;
  private issuerPromise: Promise<string> | null = null;

  constructor(private readonly config: ConfigService<Env, true>) {}

  private async getIssuer(): Promise<string> {
    if (!this.issuerPromise) {
      this.issuerPromise = (async () => {
        const tenantId = this.config.get('AZUREAD_TENANT_ID', { infer: true });
        const clientId = this.config.get('AZUREAD_CLIENT_ID', { infer: true });
        const clientSecret = this.config.get('AZUREAD_CLIENT_SECRET', { infer: true });
        const cfg = await discoverAzureAdConfiguration(tenantId, clientId, clientSecret);
        return cfg.serverMetadata().issuer as string;
      })();
    }
    return this.issuerPromise;
  }

  private async getJwks() {
    if (!this.jwksPromise) {
      this.jwksPromise = (async () => {
        const tenantId = this.config.get('AZUREAD_TENANT_ID', { infer: true });
        const clientId = this.config.get('AZUREAD_CLIENT_ID', { infer: true });
        const clientSecret = this.config.get('AZUREAD_CLIENT_SECRET', { infer: true });
        const cfg = await discoverAzureAdConfiguration(tenantId, clientId, clientSecret);
        const jwksUri = cfg.serverMetadata().jwks_uri as string;
        return createRemoteJWKSet(new URL(jwksUri));
      })();
    }
    return this.jwksPromise;
  }

  async verifyBearerToken(token: string): Promise<{ claims: AzureAdJwtClaims }> {
    try {
      const jwks = await this.getJwks();
      const issuer = await this.getIssuer();
      const audience = this.config.get('AZUREAD_CLIENT_ID', { infer: true });

      const { payload } = await jwtVerify(token, jwks, {
        issuer,
        audience,
      });

      return { claims: payload as unknown as AzureAdJwtClaims };
    } catch (e) {
      throw new UnauthorizedException('Invalid bearer token.');
    }
  }
}

