using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Microsoft.EntityFrameworkCore;


namespace OpenIdDictMvcContext.Data
{
    public class OidcUserGroupConfiguration : IEntityTypeConfiguration<OidcUserGroup>
    {

        public void Configure(EntityTypeBuilder<OidcUserGroup> builder)
        {
            builder.HasKey(p => new { p.OidcUserId, p.OidcGroupId });
            builder.HasOne(e => e.User)
                   .WithMany(e => e.UserGroups)
                   .HasForeignKey(e => e.OidcUserId)
                   .IsRequired()
                   .OnDelete(DeleteBehavior.ClientCascade);
            builder.HasOne(e => e.Group)
                   .WithMany(e => e.UserGroups)
                   .HasForeignKey(e => e.OidcGroupId)
                   .IsRequired()
                   .OnDelete(DeleteBehavior.ClientCascade);
            builder.Property(b => b.OidcGroupId).IsRequired().HasMaxLength(50);
        }
    }
}

