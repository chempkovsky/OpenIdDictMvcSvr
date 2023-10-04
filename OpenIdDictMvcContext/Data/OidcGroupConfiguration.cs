using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace OpenIdDictMvcContext.Data
{
    public class OidcGroupConfiguration : IEntityTypeConfiguration<OidcGroup>
    {
        public void Configure(EntityTypeBuilder<OidcGroup> builder)
        {
            builder.HasKey(p => p.OidcGroupId );
            builder.HasAlternateKey(p => new { p.OidcGroupName });
            builder.Property(b => b.OidcGroupId).IsRequired().HasMaxLength(50);
            builder.Property(b => b.OidcGroupName).IsRequired().HasMaxLength(100);
            builder.Property(b => b.OidcGroupDisplayName).HasMaxLength(200);
        }
    }
}
