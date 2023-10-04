namespace OpenIdDictMvcLib.Confs
{
    public class IdentityConf
    {
        public class PasswordConf
        {
            public const string SectionPath = "Identity:Password";
            public int? RequiredLength { get; set; }
            public int? RequiredUniqueChars { get; set; }
            public bool? RequireNonAlphanumeric { get; set; }
            public bool? RequireLowercase { get; set; }
            public bool? RequireUppercase { get; set; }
            public bool? RequireDigit { get; set; }
        }
        public class LockoutConf
        {
            public const string SectionPath = "Identity:Lockout";
            public bool? AllowedForNewUsers { get; set; }
            public int? MaxFailedAccessAttempts { get; set; }
            public TimeSpan? DefaultLockoutTimeSpan { get; set; } // {"DefaultLockoutTimeSpan":"0.08:00:00"} D.HH:mm:nn
        }
        public class UserConf
        {
            public const string SectionPath = "Identity:User";
            public string? AllowedUserNameCharacters { get; set; }
            public bool? RequireUniqueEmail { get; set; }
        }
        public class ClaimsIdentityConf
        {
            public const string SectionPath = "Identity:ClaimsIdentity";
            public string? RoleClaimType { get; set; }

            public string? UserNameClaimType { get; set; }

            public string? UserIdClaimType { get; set; }

            public string? EmailClaimType { get; set; }

            public string? SecurityStampClaimType { get; set; }

        }
        public class SignInConf
        {
            public const string SectionPath = "Identity:SignIn";
            public bool? RequireConfirmedEmail { get; set; }
            public bool? RequireConfirmedPhoneNumber { get; set; }
            public bool? RequireConfirmedAccount { get; set; }
        }

        public class AnalizeScopesConf
        {
            public const string SectionPath = "Identity:Scopes";
            public bool? AnalizeUserClaims { get; set; }
            public bool? AnalizeRoleClaims { get; set; }
            public bool? AnalizeUserScopes { get; set; }
            public bool? AnalizeGroupScopes { get; set; }
        }

    }
}
