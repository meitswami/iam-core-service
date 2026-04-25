"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.EnvSchema = void 0;
const zod_1 = require("zod");
exports.EnvSchema = zod_1.z.object({
    NODE_ENV: zod_1.z.enum(['development', 'test', 'uat', 'production']).default('development'),
    PORT: zod_1.z.coerce.number().int().min(1).max(65535).default(3000),
    APP_PUBLIC_URL: zod_1.z.string().url(),
    API_PUBLIC_URL: zod_1.z.string().url(),
    DATABASE_URL: zod_1.z.string().min(1),
    COOKIE_DOMAIN: zod_1.z.string().optional(),
    SESSION_COOKIE_NAME: zod_1.z.string().default('__Host-iam_session'),
    SESSION_TTL_SECONDS: zod_1.z.coerce.number().int().min(300).max(60 * 60 * 24 * 30).default(60 * 60 * 8),
    TOKEN_ENC_KEY_B64: zod_1.z.string().min(1),
    AZUREAD_TENANT_ID: zod_1.z.string().min(1),
    AZUREAD_CLIENT_ID: zod_1.z.string().min(1),
    AZUREAD_CLIENT_SECRET: zod_1.z.string().min(1),
    AZUREAD_REDIRECT_URI: zod_1.z.string().url(),
    AZUREAD_SCOPES: zod_1.z.string().default('openid profile email offline_access'),
    ZOHO_CLIENT_ID: zod_1.z.string().optional(),
    ZOHO_CLIENT_SECRET: zod_1.z.string().optional(),
    ZOHO_REDIRECT_URI: zod_1.z.string().url().optional(),
    ZOHO_SCOPES: zod_1.z.string().default('openid profile email offline_access'),
    ENABLE_SWAGGER: zod_1.z.coerce.boolean().default(false),
});
//# sourceMappingURL=env.schema.js.map