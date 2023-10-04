using NuGet.Packaging;

namespace OidcMvcClient
{

    // <ItemGroup>
    //    ...
    //    <PackageReference Include = "Microsoft.AspNetCore.Authentication.JwtBearer" Version="6.0.6" />
    //    <PackageReference Include = "IdentityModel.AspNetCore.OAuth2Introspection" Version="6.2.0" />
    //    ...
    // </ItemGroup>

    /*
    public static class Selector
    {
        public static (string, string) GetSchemeAndCredential(HttpContext context)
        {
            var header = context.Request.Headers["Authorization"].FirstOrDefault();

            if (string.IsNullOrEmpty(header))
            {
                return ("", "");
            }

            var parts = header.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length != 2)
            {
                return ("", "");
            }

            return (parts[0], parts[1]);
        }
        public static Func<HttpContext, string> ForwardReferenceToken(string introspectionScheme = "introspection")
        {
            string Select(HttpContext context)
            {
                var (scheme, credential) = GetSchemeAndCredential(context);

                if ("Bearer".Equals(scheme, StringComparison.OrdinalIgnoreCase) && (!string.IsNullOrEmpty(credential))
                    &&(credential.Length < 60))
                {
                    return introspectionScheme;
                }

                return null;
            }

            return Select;
        }
    }
    */
}
