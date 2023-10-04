namespace OpenIdDictMvcContext.Data
{
    public class OidcUserScope : OidcUserScope<string, OidcIdentityUser>
    {
    }

    public class OidcUserScope<TKey, TOidcIdentityUser>
        where TKey : notnull, IEquatable<TKey>
        where TOidcIdentityUser : class
    {
        public virtual TKey? OidcUserId { get; set; }
        public virtual string? OidcAppName { get; set; }
        public virtual string? OidcScopes { get; set; }
        public virtual string? OidcAudiences { get; set; }
        public virtual TOidcIdentityUser User { get; set; } = null!;
    }

}
