import { discovery } from 'openid-client';

export async function discoverAzureAdConfiguration(
  tenantId: string,
  clientId: string,
  clientSecret: string,
) {
  const wellKnown = new URL(
    `https://login.microsoftonline.com/${tenantId}/v2.0/.well-known/openid-configuration`,
  );
  // Passing clientSecret as string is shorthand for { client_secret } and uses ClientSecretPost by default.
  return discovery(wellKnown, clientId, clientSecret);
}

