using static OpenIddict.Abstractions.OpenIddictConstants;

namespace OpenIdDictMvcLib.Helpers
{
    public static class PermissionItems
    {
        public static string[] Items =
        {
                Permissions.Endpoints.Authorization,
                Permissions.Endpoints.Device,
                Permissions.Endpoints.Introspection,
                Permissions.Endpoints.Logout,
                Permissions.Endpoints.Revocation,
                Permissions.Endpoints.Token,

                Permissions.GrantTypes.AuthorizationCode,
                Permissions.GrantTypes.ClientCredentials,
                Permissions.GrantTypes.DeviceCode,
                Permissions.GrantTypes.Implicit,
                Permissions.GrantTypes.Password,
                Permissions.GrantTypes.RefreshToken,

                Permissions.ResponseTypes.Code,
                Permissions.ResponseTypes.CodeIdToken,
                Permissions.ResponseTypes.CodeIdTokenToken,
                Permissions.ResponseTypes.CodeToken,
                Permissions.ResponseTypes.IdToken,
                Permissions.ResponseTypes.IdTokenToken,
                Permissions.ResponseTypes.None,
                Permissions.ResponseTypes.Token,

                Permissions.Scopes.Address,
                Permissions.Scopes.Email,
                Permissions.Scopes.Phone,
                Permissions.Scopes.Profile,
                Permissions.Scopes.Roles,
        };
    }
}
