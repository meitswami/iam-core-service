import { discovery } from 'openid-client';

export async function discoverZohoConfiguration(
  accountsUrl: string,
  clientId: string,
  clientSecret: string,
) {
  // Zoho OIDC discovery: https://accounts.zoho.<dc>/.well-known/openid-configuration
  const wellKnown = new URL('/.well-known/openid-configuration', accountsUrl);
  return discovery(wellKnown, clientId, clientSecret);
}

