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
var __param = (this && this.__param) || function (paramIndex, decorator) {
    return function (target, key) { decorator(target, key, paramIndex); }
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.AuthController = void 0;
const common_1 = require("@nestjs/common");
const throttler_1 = require("@nestjs/throttler");
const config_1 = require("@nestjs/config");
const auth_service_1 = require("./auth.service");
function getIp(req) {
    return req.ip;
}
let AuthController = class AuthController {
    auth;
    config;
    constructor(auth, config) {
        this.auth = auth;
        this.config = config;
    }
    async login(res) {
        const init = await this.auth.beginLogin('azuread');
        res.cookie('__Host-oidc_state', init.state, { httpOnly: true, secure: true, sameSite: 'lax', path: '/auth' });
        res.cookie('__Host-oidc_nonce', init.nonce, { httpOnly: true, secure: true, sameSite: 'lax', path: '/auth' });
        res.cookie('__Host-oidc_cv', init.codeVerifier, { httpOnly: true, secure: true, sameSite: 'lax', path: '/auth' });
        return res.redirect(302, init.url);
    }
    async callback(req, res, code, state) {
        if (!code || !state)
            return res.status(400).send('Missing code/state.');
        const expectedState = req.cookies?.['__Host-oidc_state'];
        const expectedNonce = req.cookies?.['__Host-oidc_nonce'];
        const codeVerifier = req.cookies?.['__Host-oidc_cv'];
        if (!expectedState || !expectedNonce || !codeVerifier)
            return res.status(400).send('Missing login state.');
        res.clearCookie('__Host-oidc_state', { path: '/auth' });
        res.clearCookie('__Host-oidc_nonce', { path: '/auth' });
        res.clearCookie('__Host-oidc_cv', { path: '/auth' });
        const { sessionId } = await this.auth.handleAzureCallback({
            code,
            state,
            expectedState,
            expectedNonce,
            codeVerifier,
            ip: getIp(req),
            userAgent: req.get('user-agent') ?? undefined,
        });
        const cookieName = this.config.get('SESSION_COOKIE_NAME', { infer: true });
        const ttlSeconds = this.config.get('SESSION_TTL_SECONDS', { infer: true });
        const cookieDomain = this.config.get('COOKIE_DOMAIN', { infer: true });
        res.cookie(cookieName, sessionId, {
            httpOnly: true,
            secure: true,
            sameSite: 'lax',
            path: '/',
            domain: cookieDomain,
            maxAge: ttlSeconds * 1000,
        });
        const appUrl = this.config.get('APP_PUBLIC_URL', { infer: true });
        return res.redirect(302, `${appUrl}/auth/success`);
    }
    async logout(req, res) {
        const cookieName = this.config.get('SESSION_COOKIE_NAME', { infer: true });
        const cookieDomain = this.config.get('COOKIE_DOMAIN', { infer: true });
        const sessionId = req.cookies?.[cookieName] ?? undefined;
        if (sessionId)
            await this.auth.logout(sessionId, getIp(req), req.get('user-agent') ?? undefined);
        res.clearCookie(cookieName, { path: '/', domain: cookieDomain });
        const appUrl = this.config.get('APP_PUBLIC_URL', { infer: true });
        return res.redirect(302, `${appUrl}/`);
    }
    async me(req) {
        const cookieName = this.config.get('SESSION_COOKIE_NAME', { infer: true });
        const sessionId = req.cookies?.[cookieName] ?? undefined;
        if (!sessionId)
            return { authenticated: false };
        const user = await this.auth.getMe(sessionId);
        return { authenticated: true, user };
    }
};
exports.AuthController = AuthController;
__decorate([
    (0, common_1.Get)('login'),
    (0, throttler_1.Throttle)({ default: { limit: 10, ttl: 60_000 } }),
    __param(0, (0, common_1.Res)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [Object]),
    __metadata("design:returntype", Promise)
], AuthController.prototype, "login", null);
__decorate([
    (0, common_1.Get)('callback'),
    (0, throttler_1.Throttle)({ default: { limit: 20, ttl: 60_000 } }),
    __param(0, (0, common_1.Req)()),
    __param(1, (0, common_1.Res)()),
    __param(2, (0, common_1.Query)('code')),
    __param(3, (0, common_1.Query)('state')),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [Object, Object, String, String]),
    __metadata("design:returntype", Promise)
], AuthController.prototype, "callback", null);
__decorate([
    (0, common_1.Get)('logout'),
    __param(0, (0, common_1.Req)()),
    __param(1, (0, common_1.Res)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [Object, Object]),
    __metadata("design:returntype", Promise)
], AuthController.prototype, "logout", null);
__decorate([
    (0, common_1.Get)('me'),
    __param(0, (0, common_1.Req)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [Object]),
    __metadata("design:returntype", Promise)
], AuthController.prototype, "me", null);
exports.AuthController = AuthController = __decorate([
    (0, common_1.Controller)('auth'),
    (0, common_1.UseGuards)(throttler_1.ThrottlerGuard),
    __metadata("design:paramtypes", [auth_service_1.AuthService,
        config_1.ConfigService])
], AuthController);
//# sourceMappingURL=auth.controller.js.map