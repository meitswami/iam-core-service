import { z } from 'zod';
export declare const EnvSchema: z.ZodObject<{
    NODE_ENV: z.ZodDefault<z.ZodEnum<{
        development: "development";
        test: "test";
        uat: "uat";
        production: "production";
    }>>;
    PORT: z.ZodDefault<z.ZodCoercedNumber<unknown>>;
    APP_PUBLIC_URL: z.ZodString;
    API_PUBLIC_URL: z.ZodString;
    DATABASE_URL: z.ZodString;
    COOKIE_DOMAIN: z.ZodOptional<z.ZodString>;
    SESSION_COOKIE_NAME: z.ZodDefault<z.ZodString>;
    SESSION_TTL_SECONDS: z.ZodDefault<z.ZodCoercedNumber<unknown>>;
    TOKEN_ENC_KEY_B64: z.ZodString;
    AZUREAD_TENANT_ID: z.ZodString;
    AZUREAD_CLIENT_ID: z.ZodString;
    AZUREAD_CLIENT_SECRET: z.ZodString;
    AZUREAD_REDIRECT_URI: z.ZodString;
    AZUREAD_SCOPES: z.ZodDefault<z.ZodString>;
    ZOHO_CLIENT_ID: z.ZodOptional<z.ZodString>;
    ZOHO_CLIENT_SECRET: z.ZodOptional<z.ZodString>;
    ZOHO_REDIRECT_URI: z.ZodOptional<z.ZodString>;
    ZOHO_SCOPES: z.ZodDefault<z.ZodString>;
    ENABLE_SWAGGER: z.ZodDefault<z.ZodCoercedBoolean<unknown>>;
}, z.core.$strip>;
export type Env = z.infer<typeof EnvSchema>;
