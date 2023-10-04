using static OpenIddict.Abstractions.OpenIddictConstants;
using System.Security.Claims;

namespace OpenIdDictMvcLib.Helpers
{
    public static class OpenIdExtensions
    {
        public static string GetUserIdentifier(this ClaimsIdentity identity)
            => identity.FindFirst(Claims.Subject)?.Value ??
               identity.FindFirst(ClaimTypes.NameIdentifier)?.Value ??
               identity.FindFirst(ClaimTypes.Upn)?.Value ??
               throw new InvalidOperationException("No suitable user identifier can be found in the identity.");

        public static string GetUserIdentifier(this ClaimsPrincipal principal)
            => principal.FindFirst(Claims.Subject)?.Value ??
               principal.FindFirst(ClaimTypes.NameIdentifier)?.Value ??
               principal.FindFirst(ClaimTypes.Upn)?.Value ??
               throw new InvalidOperationException("No suitable user identifier can be found in the principal.");

        public static string GetUserName(this ClaimsPrincipal principal)
            => principal.FindFirst(Claims.Name)?.Value ??
               principal.FindFirst(ClaimTypes.Name)?.Value ??
               throw new InvalidOperationException("No suitable user name can be found in the principal.");

        public static async Task<bool> AnyAsync<T>(this IAsyncEnumerable<T> source)
        {
            if (source == null)
            {
                throw new ArgumentNullException(nameof(source));
            }

            await using var enumerator = source.GetAsyncEnumerator();
            return await enumerator.MoveNextAsync();
        }

        public static Task<List<T>> ToListAsync<T>(this IAsyncEnumerable<T> source)
        {
            if (source == null)
            {
                throw new ArgumentNullException(nameof(source));
            }

            return ExecuteAsync();

            async Task<List<T>> ExecuteAsync()
            {
                var list = new List<T>();

                await foreach (var element in source)
                {
                    list.Add(element);
                }

                return list;
            }
        }
    }
}
