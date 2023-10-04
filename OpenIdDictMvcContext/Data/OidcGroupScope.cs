namespace OpenIdDictMvcContext.Data
{
    public class OidcGroupScope : OidcGroupScope<string, OidcGroup>
    {
    }

    public class OidcGroupScope<TKey, TOidcGroup>
        where TKey : notnull, IEquatable<TKey>
        where TOidcGroup : class
    {
        public virtual TKey? OidcGroupId { get; set; }
        public virtual string? OidcAppName { get; set; }
        public virtual string? OidcScopes { get; set; }
        public virtual string? OidcAudiences { get; set; }

        public virtual TOidcGroup Group { get; } = null!;
    }

}
