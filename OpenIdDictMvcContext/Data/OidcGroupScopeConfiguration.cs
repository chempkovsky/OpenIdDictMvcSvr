using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace OpenIdDictMvcContext.Data
{
    public class OidcGroupScopeConfiguration : IEntityTypeConfiguration<OidcGroupScope>
    {
        public void Configure(EntityTypeBuilder<OidcGroupScope> builder)
        {
            builder.HasKey(p => new { p.OidcGroupId, p.OidcAppName });
            builder.HasOne(e => e.Group)
                   .WithMany(e => e.GroupScopes)
                   .HasForeignKey(e => e.OidcGroupId)
                   .IsRequired()
                   .OnDelete(DeleteBehavior.Cascade);
            builder.Property(b => b.OidcGroupId).IsRequired().HasMaxLength(50);
            builder.Property(b => b.OidcAppName).IsRequired().HasMaxLength(100);
            builder.Property(b => b.OidcScopes).IsRequired().HasMaxLength(500);
        }
    }
}
