import { ConfigService } from '@nestjs/config';
import type { Env } from '../../../config/env.schema';
import { PrismaService } from '../../../prisma/prisma.service';
import { TokenCryptoService } from '../../../crypto/token-crypto.service';
import { AuditService } from '../audit/audit.service';
import type { AuthProvider, AuthenticatedUser } from './auth.types';
type LoginInit = {
    url: string;
    state: string;
    nonce: string;
    codeVerifier: string;
};
export declare class AuthService {
    private readonly config;
    private readonly prisma;
    private readonly crypto;
    private readonly audit;
    private azureConfigPromise;
    constructor(config: ConfigService<Env, true>, prisma: PrismaService, crypto: TokenCryptoService, audit: AuditService);
    private getAzureConfig;
    beginLogin(provider: AuthProvider): Promise<LoginInit>;
    handleAzureCallback(args: {
        code: string;
        state: string;
        expectedState: string;
        expectedNonce: string;
        codeVerifier: string;
        ip?: string;
        userAgent?: string;
    }): Promise<{
        sessionId: string;
        user: AuthenticatedUser;
    }>;
    logout(sessionId: string, ip?: string, userAgent?: string): Promise<void>;
    getMe(sessionId: string): Promise<AuthenticatedUser>;
    private resolveRolesForUser;
}
export {};
