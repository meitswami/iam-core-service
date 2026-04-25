"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.discoverAzureAdConfiguration = discoverAzureAdConfiguration;
const openid_client_1 = require("openid-client");
async function discoverAzureAdConfiguration(tenantId, clientId, clientSecret) {
    const wellKnown = new URL(`https://login.microsoftonline.com/${tenantId}/v2.0/.well-known/openid-configuration`);
    return (0, openid_client_1.discovery)(wellKnown, clientId, clientSecret);
}
//# sourceMappingURL=azuread.oidc.js.map