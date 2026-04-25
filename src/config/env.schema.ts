import { z } from 'zod';

export const EnvSchema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'uat', 'production']).default('development'),
  PORT: z.coerce.number().int().min(1).max(65535).default(3000),

  APP_PUBLIC_URL: z.string().url(), // e.g. https://app.dev.example.com
  API_PUBLIC_URL: z.string().url(), // e.g. https://api.dev.example.com

  DATABASE_URL: z.string().min(1),

  // Cookie/session hardening
  COOKIE_DOMAIN: z.string().optional(), // set in prod (e.g. .example.com)
  SESSION_COOKIE_NAME: z.string().default('__Host-iam_session'),
  SESSION_TTL_SECONDS: z.coerce.number().int().min(300).max(60 * 60 * 24 * 30).default(60 * 60 * 8),

  // Used to encrypt tokens at rest in DB (AES-256-GCM). Must be 32 bytes base64.
  TOKEN_ENC_KEY_B64: z.string().min(1),

  // Azure AD (primary)
  AZUREAD_TENANT_ID: z.string().min(1),
  AZUREAD_CLIENT_ID: z.string().min(1),
  AZUREAD_CLIENT_SECRET: z.string().min(1),
  AZUREAD_REDIRECT_URI: z.string().url(), // backend callback URL
  AZUREAD_SCOPES: z.string().default('openid profile email offline_access'),

  // Optional Zoho (secondary)
  ZOHO_CLIENT_ID: z.string().optional(),
  ZOHO_CLIENT_SECRET: z.string().optional(),
  ZOHO_REDIRECT_URI: z.string().url().optional(),
  ZOHO_SCOPES: z.string().default('openid profile email offline_access'),

  // Feature toggles
  ENABLE_SWAGGER: z.coerce.boolean().default(false),
});

export type Env = z.infer<typeof EnvSchema>;

