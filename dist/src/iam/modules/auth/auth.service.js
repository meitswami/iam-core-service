"use strict";
var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.AuthService = void 0;
const common_1 = require("@nestjs/common");
const config_1 = require("@nestjs/config");
const openid_client_1 = require("openid-client");
const prisma_service_1 = require("../../../prisma/prisma.service");
const token_crypto_service_1 = require("../../../crypto/token-crypto.service");
const audit_service_1 = require("../audit/audit.service");
const azuread_oidc_1 = require("./providers/azuread.oidc");
let AuthService = class AuthService {
    config;
    prisma;
    crypto;
    audit;
    azureConfigPromise = null;
    constructor(config, prisma, crypto, audit) {
        this.config = config;
        this.prisma = prisma;
        this.crypto = crypto;
        this.audit = audit;
    }
    async getAzureConfig() {
        if (!this.azureConfigPromise) {
            const tenantId = this.config.get('AZUREAD_TENANT_ID', { infer: true });
            const clientId = this.config.get('AZUREAD_CLIENT_ID', { infer: true });
            const clientSecret = this.config.get('AZUREAD_CLIENT_SECRET', { infer: true });
            this.azureConfigPromise = (0, azuread_oidc_1.discoverAzureAdConfiguration)(tenantId, clientId, clientSecret);
        }
        return this.azureConfigPromise;
    }
    async beginLogin(provider) {
        if (provider !== 'azuread')
            throw new common_1.UnauthorizedException('Provider not enabled.');
        const state = (0, openid_client_1.randomState)();
        const nonce = (0, openid_client_1.randomNonce)();
        const codeVerifier = (0, openid_client_1.randomPKCECodeVerifier)();
        const codeChallenge = await (0, openid_client_1.calculatePKCECodeChallenge)(codeVerifier);
        const scopes = this.config.get('AZUREAD_SCOPES', { infer: true }).split(/\s+/).filter(Boolean);
        const cfg = await this.getAzureConfig();
        const redirectUri = this.config.get('AZUREAD_REDIRECT_URI', { infer: true });
        const url = (0, openid_client_1.buildAuthorizationUrl)(cfg, {
            redirect_uri: redirectUri,
            scope: scopes.join(' '),
            state,
            nonce,
            code_challenge: codeChallenge,
            code_challenge_method: 'S256',
        });
        return { url: url.toString(), state, nonce, codeVerifier };
    }
    async handleAzureCallback(args) {
        if (args.state !== args.expectedState)
            throw new common_1.UnauthorizedException('Invalid OAuth state.');
        const cfg = await this.getAzureConfig();
        const redirectUri = this.config.get('AZUREAD_REDIRECT_URI', { infer: true });
        const callbackUrl = new URL(redirectUri);
        callbackUrl.searchParams.set('code', args.code);
        callbackUrl.searchParams.set('state', args.state);
        const tokens = await (0, openid_client_1.authorizationCodeGrant)(cfg, callbackUrl, {
            pkceCodeVerifier: args.codeVerifier,
            expectedState: args.expectedState,
            expectedNonce: args.expectedNonce,
        });
        const claims = tokens.claims();
        if (!claims)
            throw new common_1.UnauthorizedException('Missing ID token claims.');
        const externalId = claims.oid ?? claims.sub;
        if (!externalId)
            throw new common_1.UnauthorizedException('Missing user identifier from IdP.');
        const email = claims.preferred_username ?? claims.email;
        const displayName = claims.name ?? undefined;
        const upn = claims.upn ?? undefined;
        const groups = Array.isArray(claims.groups) ? claims.groups : [];
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
        const roleKeys = await this.resolveRolesForUser({
            userId: user.id,
            provider: 'azuread',
            tenantId: claims.tid,
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
    async logout(sessionId, ip, userAgent) {
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
    async getMe(sessionId) {
        const session = await this.prisma.session.findFirst({
            where: { id: sessionId, revokedAt: null, expiresAt: { gt: new Date() } },
            include: { user: true },
        });
        if (!session)
            throw new common_1.UnauthorizedException('Invalid session.');
        await this.prisma.session.update({ where: { id: session.id }, data: { lastSeenAt: new Date() } });
        const roleKeys = await this.resolveRolesForUser({
            userId: session.userId,
            provider: session.user.provider,
            tenantId: session.user.tenantId ?? undefined,
            groups: session.user.groups,
        });
        return {
            userId: session.userId,
            provider: session.user.provider,
            externalId: session.user.externalId,
            email: session.user.email ?? undefined,
            displayName: session.user.displayName ?? undefined,
            roles: roleKeys,
        };
    }
    async resolveRolesForUser(args) {
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
        const roles = new Set();
        for (const m of groupRoleMaps)
            roles.add(m.role.key);
        for (const b of overrides)
            roles.add(b.role.key);
        if (roles.size === 0)
            roles.add('User');
        return [...roles].sort();
    }
};
exports.AuthService = AuthService;
exports.AuthService = AuthService = __decorate([
    (0, common_1.Injectable)(),
    __metadata("design:paramtypes", [config_1.ConfigService,
        prisma_service_1.PrismaService,
        token_crypto_service_1.TokenCryptoService,
        audit_service_1.AuditService])
], AuthService);
//# sourceMappingURL=auth.service.js.map