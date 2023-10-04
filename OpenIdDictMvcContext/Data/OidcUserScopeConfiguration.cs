using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace OpenIdDictMvcContext.Data
{
    public class OidcUserScopeConfiguration : IEntityTypeConfiguration<OidcUserScope>
    {
        public void Configure(EntityTypeBuilder<OidcUserScope> builder)
        {
            builder.HasKey(p => new { p.OidcUserId, p.OidcAppName });
            builder.HasOne(e => e.User)
                   .WithMany(e => e.UserScopes)
                   .HasForeignKey(e => e.OidcUserId)
                   .IsRequired()
                   .OnDelete(DeleteBehavior.ClientCascade);
            builder.Property(b => b.OidcAppName).IsRequired().HasMaxLength(100);
            builder.Property(b => b.OidcScopes).IsRequired().HasMaxLength(500);
        }
    }
}
