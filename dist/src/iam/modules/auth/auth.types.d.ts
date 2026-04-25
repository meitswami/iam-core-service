export type AuthProvider = 'azuread' | 'zoho';
export type AuthenticatedUser = {
    userId: string;
    provider: AuthProvider;
    externalId: string;
    email?: string;
    displayName?: string;
    roles: string[];
};
