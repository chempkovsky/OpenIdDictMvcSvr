using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;


namespace OpenIdDictMvcContext.Data
{
    public class ApplicationDbContext : IdentityDbContext<OidcIdentityUser, OidcIdentityRole, string>
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
            : base(options)
        {
          //  Database.EnsureCreated();
        }

        protected ApplicationDbContext():base() {
          //  Database.EnsureCreated();
        }


        public DbSet<OidcUserGroup> OidcUserGroups { get; set; } = null!;
        public DbSet<OidcGroup> OidcGroups { get; set; } = null!;
        public DbSet<OidcGroupScope> OidcGroupScopes { get; set; } = null!;
        public DbSet<OidcUserScope> OidcUserScopes { get; set; } = null!;

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);
            modelBuilder.ApplyConfiguration(new OidcGroupConfiguration());
            modelBuilder.ApplyConfiguration(new OidcUserGroupConfiguration());
            modelBuilder.ApplyConfiguration(new OidcGroupScopeConfiguration());
            modelBuilder.ApplyConfiguration(new OidcUserScopeConfiguration());
        }

    }
}