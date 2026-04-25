# IAM Core Service (Backend) — Local SSO Login Setup

This backend is the **IAM/BFF layer**: it performs the OIDC Authorization Code flow with Azure AD and stores tokens **server-side**. The frontend only receives an **HttpOnly session cookie**.

## Prereqs

- Node.js + npm
- PostgreSQL running locally (or a reachable DB)

## Configure environment

Copy `.env.example` to `.env` and fill:

- `DATABASE_URL`
- `TOKEN_ENC_KEY_B64`
- `AZUREAD_*` values

## Start Postgres quickly (example)

Create DB/user matching your `DATABASE_URL`.

## Generate Prisma client + migrate

```bash
npx prisma generate
npx prisma migrate dev --name init
```

## Run the API

```bash
npm run start:dev
```

## Test login

- Frontend calls `GET /auth/login` (redirect to Azure AD)
- Azure AD redirects to `GET /auth/callback`
- Backend sets `__Host-iam_session` cookie and redirects to `APP_PUBLIC_URL/auth/success`
- Frontend calls `GET /auth/me` with credentials to read session identity

