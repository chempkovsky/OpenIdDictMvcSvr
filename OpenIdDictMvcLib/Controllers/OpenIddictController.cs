using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Primitives;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using static OpenIddict.Abstractions.OpenIddictConstants;
using System.Collections.Immutable;
using System.Security.Claims;
using Microsoft.Extensions.Localization;
using OpenIdDictMvcLib.Localizers;
using OpenIdDictMvcContext.Data;
using OpenIdDictMvcLib.Dto;
using OpenIdDictMvcLib.ActionAttributes;
using OpenIdDictMvcLib.Helpers;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Client.AspNetCore;
using static OpenIddict.Client.WebIntegration.OpenIddictClientWebIntegrationConstants;
using OpenIdDictMvcLib.Confs;
using Microsoft.Extensions.Configuration;
using Microsoft.AspNetCore.Http;
using System.Security.Cryptography;

namespace OpenIdDictMvcLib.Controllers
{
    // Note: the error descriptions used in this controller are deliberately not localized as
    // the OAuth 2.0 specification only allows select US-ASCII characters in error_description.
    public class OpenIddictController : Controller
    {
        private readonly IOpenIddictApplicationManager _applicationManager;
        private readonly IOpenIddictAuthorizationManager _authorizationManager;
        private readonly IOpenIddictScopeManager _scopeManager;
        private readonly SignInManager<OidcIdentityUser> _signInManager;
        private readonly UserManager<OidcIdentityUser> _userManager;
        private readonly RoleManager<OidcIdentityRole> _roleManager;
        private readonly IConfiguration _configuration;
        private readonly IStringLocalizer<OpenIddictLocalizerResource> _sharedLocalizer;
        private readonly ApplicationDbContext _context;
        private readonly string _claimprefixval = "";
        private readonly string _roleprefixval = "";
        private bool AnalizeUserScopes = false;
        private bool AnalizeGroupScopes = false;

        public OpenIddictController(
            ApplicationDbContext context,
            IOpenIddictApplicationManager applicationManager,
            IOpenIddictAuthorizationManager authorizationManager,
            IOpenIddictScopeManager scopeManager,
            SignInManager<OidcIdentityUser> signInManager,
            UserManager<OidcIdentityUser> userManager,
            RoleManager<OidcIdentityRole> roleManager,
            IConfiguration configuration,
            IStringLocalizer<OpenIddictLocalizerResource> sharedLocalizer
            )
        {
            _context = context;
            _applicationManager = applicationManager;
            _authorizationManager = authorizationManager;
            _scopeManager = scopeManager;
            _signInManager = signInManager;
            _userManager = userManager;
            _roleManager = roleManager;
            _configuration = configuration;
            _sharedLocalizer = sharedLocalizer;

            _claimprefixval = _configuration[nameof(OidcAllowedScope) + ":" + nameof(OidcAllowedScope.ClaimPrefix)];
            if (string.IsNullOrEmpty(_claimprefixval)) _claimprefixval = OidcAllowedScope.ClaimPrefix + "."; else _claimprefixval += ".";
            _roleprefixval = _configuration[nameof(OidcAllowedScope) + ":" + nameof(OidcAllowedScope.RolePrefix)];
            if (string.IsNullOrEmpty(_roleprefixval)) _roleprefixval = OidcAllowedScope.RolePrefix + "."; else _roleprefixval += ".";

            var analizeScopes = new IdentityConf.AnalizeScopesConf();
            _configuration.GetSection(IdentityConf.AnalizeScopesConf.SectionPath).Bind(analizeScopes);

            AnalizeUserScopes  = analizeScopes.AnalizeUserScopes.HasValue ? analizeScopes.AnalizeUserScopes.Value : false;
            AnalizeGroupScopes = analizeScopes.AnalizeGroupScopes.HasValue ? analizeScopes.AnalizeGroupScopes.Value : false;

        }

        // https://github.com/OrchardCMS/OrchardCore/blob/main/src/OrchardCore.Modules/OrchardCore.OpenId/Controllers/AccessController.cs

        #region Authorize
        [HttpGet("~/connect/authorize")]
        [HttpPost("~/connect/authorize")]
        [IgnoreAntiforgeryToken]
        public async Task<IActionResult> Authorize()
        {
            var request = HttpContext.GetOpenIddictServerRequest() ??
                throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");
            
            // Try to retrieve the user principal stored in the authentication cookie and redirect
            // the user agent to the login page (or to an external provider) in the following cases:
            //
            //  - If the user principal can't be extracted or the cookie is too old.
            //  - If prompt=login was specified by the client application.
            //  - If a max_age parameter was provided and the authentication cookie is not considered "fresh" enough.
            //
            // For scenarios where the default authentication handler configured in the ASP.NET Core
            // authentication options shouldn't be used, a specific scheme can be specified here.
            var result = await HttpContext.AuthenticateAsync();
            if (result == null || !result.Succeeded || request.HasPrompt(Prompts.Login) ||
               (request.MaxAge != null && result.Properties?.IssuedUtc != null &&
                DateTimeOffset.UtcNow - result.Properties.IssuedUtc > TimeSpan.FromSeconds(request.MaxAge.Value)))
            {
                // If the client application requested promptless authentication,
                // return an error indicating that the user is not logged in.
                if (request.HasPrompt(Prompts.None))
                {
                    return Forbid(
                        authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                        properties: new AuthenticationProperties(new Dictionary<string, string?>
                        {
                            [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.LoginRequired,
                            [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "The user is not logged in."
                        }));
                }

                // To avoid endless login -> authorization redirects, the prompt=login flag
                // is removed from the authorization request payload before redirecting the user.
                var prompt = string.Join(" ", request.GetPrompts().Remove(Prompts.Login));

                var parameters = Request.HasFormContentType ?
                    Request.Form.Where(parameter => parameter.Key != Parameters.Prompt).ToList() :
                    Request.Query.Where(parameter => parameter.Key != Parameters.Prompt).ToList();

                parameters.Add(KeyValuePair.Create(Parameters.Prompt, new StringValues(prompt)));

                // For applications that want to allow the client to select the external authentication provider
                // that will be used to authenticate the user, the identity_provider parameter can be used for that.
                if (!string.IsNullOrEmpty(request.IdentityProvider))
                {
                    if (!string.Equals(request.IdentityProvider, Providers.GitHub, StringComparison.Ordinal))
                    {
                        return Forbid(
                            authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                            properties: new AuthenticationProperties(new Dictionary<string, string?>
                            {
                                [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidRequest,
                                [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
                                    "The specified identity provider is not valid."
                            }));
                    }

                    var properties = _signInManager.ConfigureExternalAuthenticationProperties(
                        provider: request.IdentityProvider,
                        redirectUrl: Url.Action("ExternalLoginCallback", "Account", new
                        {
                            ReturnUrl = Request.PathBase + Request.Path + QueryString.Create(parameters)
                        }));

                    // Note: when only one client is registered in the client options,
                    // specifying the issuer URI or the provider name is not required.
                    properties.SetString(OpenIddictClientAspNetCoreConstants.Properties.ProviderName, request.IdentityProvider);

                    // Ask the OpenIddict client middleware to redirect the user agent to the identity provider.
                    return Challenge(properties, OpenIddictClientAspNetCoreDefaults.AuthenticationScheme);
                }

                // For scenarios where the default challenge handler configured in the ASP.NET Core
                // authentication options shouldn't be used, a specific scheme can be specified here.
                return Challenge(new AuthenticationProperties
                {
                    RedirectUri = Request.PathBase + Request.Path + QueryString.Create(parameters)
                });
            }


            // Retrieve the profile of the logged in user.
            var user = await _userManager.FindByIdAsync(result.Principal.GetUserIdentifier()) ??
                throw new InvalidOperationException("The user details cannot be retrieved.");
            string clientId = request.ClientId ??
                throw new InvalidOperationException("The application details cannot be found.");
            // Retrieve the application details from the database.
            var application = await _applicationManager.FindByClientIdAsync(clientId) ??
                throw new InvalidOperationException("Details concerning the calling client application cannot be found.");
            var pscopes = request.GetScopes();
            OidcScopeADto? uscopes = null;

            if (AnalizeUserScopes || AnalizeGroupScopes)
            {
                uscopes = await GetUserScopesAsync(user, clientId);
                if(uscopes != null)
                    pscopes = uscopes.OidcScopes.Intersect(pscopes).ToImmutableArray();
            }


            // Retrieve the permanent authorizations associated with the user and the calling client application.
            var authorizations = await _authorizationManager.FindAsync(
                subject: await _userManager.GetUserIdAsync(user),
                client: clientId,
                status: Statuses.Valid,
                type: AuthorizationTypes.Permanent,
                scopes: pscopes).ToListAsync();

            switch (await _applicationManager.GetConsentTypeAsync(application))
            {
                // If the consent is external (e.g when authorizations are granted by a sysadmin),
                // immediately return an error if no authorization can be found in the database.
                case ConsentTypes.External when !authorizations.Any():
                    return Forbid(
                        authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                        properties: new AuthenticationProperties(new Dictionary<string, string?>
                        {
                            [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.ConsentRequired,
                            [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
                                "The logged in user is not allowed to access this client application."
                        }));

                // If the consent is implicit or if an authorization was found,
                // return an authorization response without displaying the consent form.
                case ConsentTypes.Implicit:
                case ConsentTypes.External when authorizations.Any():
                case ConsentTypes.Explicit when authorizations.Any() && !request.HasPrompt(Prompts.Consent):
                    // Create the claims-based identity that will be used by OpenIddict to generate tokens.
                    var identity = new ClaimsIdentity(
                        authenticationType: TokenValidationParameters.DefaultAuthenticationType,
                        nameType: Claims.Name,
                        roleType: Claims.Role);

                    // Add the claims that will be persisted in the tokens.
                    
                    if (pscopes.Contains(OpenIddictConstants.Scopes.Email))
                    {
                        identity.SetClaim(Claims.Email, await _userManager.GetEmailAsync(user));
                    }
                    if (pscopes.Contains(OpenIddictConstants.Scopes.Profile))
                    {
                        identity.SetClaim(Claims.Subject, await _userManager.GetUserIdAsync(user))
                            .SetClaim(Claims.Name, await _userManager.GetUserNameAsync(user));
                    }
                    if (pscopes.Contains(OpenIddictConstants.Scopes.Roles))
                    {
                        identity.SetClaims(Claims.Role, (await _userManager.GetRolesAsync(user)).ToImmutableArray());
                    }

                    // Note: in this sample, the granted scopes match the requested scope
                    // but you may want to allow the user to uncheck specific scopes.
                    // For that, simply restrict the list of scopes before calling SetScopes.
                    identity.SetScopes(pscopes);

                    var lstres = await _scopeManager.ListResourcesAsync(pscopes).ToListAsync();
                    if ((uscopes != null) && (lstres != null)) {
                        lstres = uscopes.OidcAudiences.Intersect(lstres).ToList();
                    }
                    identity.SetResources(lstres);

                    // Automatically create a permanent authorization to avoid requiring explicit consent
                    // for future authorization or token requests containing the same scopes.
                    var authorization = authorizations.LastOrDefault();
                    authorization ??= await _authorizationManager.CreateAsync(
                        identity: identity,
                        subject: await _userManager.GetUserIdAsync(user),
                        client: await _applicationManager.GetIdAsync(application)??"",
                        type: AuthorizationTypes.Permanent,
                        scopes: identity.GetScopes());

                    identity.SetAuthorizationId(await _authorizationManager.GetIdAsync(authorization));
                    identity.SetDestinations(GetDestinations);

                    return SignIn(new ClaimsPrincipal(identity), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

                // At this point, no authorization was found in the database and an error must be returned
                // if the client application specified prompt=none in the authorization request.
                case ConsentTypes.Explicit when request.HasPrompt(Prompts.None):
                case ConsentTypes.Systematic when request.HasPrompt(Prompts.None):
                    return Forbid(
                        authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                        properties: new AuthenticationProperties(new Dictionary<string, string?>
                        {
                            [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.ConsentRequired,
                            [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
                                "Interactive user consent is required."
                        }));

                // In every other case, render the consent form.
                default:
                    var ScpWithRes = await PrepareScopesToDisplay(pscopes, uscopes);
                    ViewBag.ScpWithRes = ScpWithRes;
                    return View(new AuthorizeDto
                    {
                        ApplicationName = clientId,
                        LocalizedApplicationName = await _applicationManager.GetLocalizedDisplayNameAsync(application),
                        UserCode = request.UserCode ?? ""
                    });
            }
        }

        [Authorize, FormValueRequired("submit.Deny")]
        [HttpPost("~/connect/authorize"), ValidateAntiForgeryToken]
        // Notify OpenIddict that the authorization grant has been denied by the resource owner
        // to redirect the user agent to the client application using the appropriate response_mode.
        public IActionResult Deny() => Forbid(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);


        [Authorize, FormValueRequired("submit.Accept")]
        [HttpPost("~/connect/authorize"), ValidateAntiForgeryToken]
        public async Task<IActionResult> Accept([Bind("ApplicationName", "Scope", "UserCode", "ScopesToAuthorize")] AuthorizeDto authorizeDto)
        {
            var request = HttpContext.GetOpenIddictServerRequest() ??
                throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

            // Retrieve the profile of the logged in user.
            var user = await _userManager.GetUserAsync(User) ??
                throw new InvalidOperationException("The user details cannot be retrieved.");

            

            // Retrieve the application details from the database.
            string clientId = request.ClientId ??
                throw new InvalidOperationException("Details concerning the calling client application cannot be found.");
            var application = await _applicationManager.FindByClientIdAsync(clientId) ??
                throw new InvalidOperationException("Details concerning the calling client application cannot be found.");
            string appId = await _applicationManager.GetIdAsync(application) ??
                throw new InvalidOperationException("Details concerning the calling client application cannot be found.");

            var pscopes = authorizeDto.ScopesToAuthorize.ToImmutableArray();

            OidcScopeADto? uscopes = null;
            if (AnalizeUserScopes || AnalizeGroupScopes)
            {
                uscopes = await GetUserScopesAsync(user, clientId);
                if (uscopes != null)
                    pscopes = uscopes.OidcScopes.Intersect(pscopes).ToImmutableArray();
            }


            // Retrieve the permanent authorizations associated with the user and the calling client application.
            var authorizations = await _authorizationManager.FindAsync(
                subject: await _userManager.GetUserIdAsync(user),
                client: appId,
                status: Statuses.Valid,
                type: AuthorizationTypes.Permanent,
                scopes: pscopes).ToListAsync();

            // Note: the same check is already made in the other action but is repeated
            // here to ensure a malicious user can't abuse this POST-only endpoint and
            // force it to return a valid response without the external authorization.
            if (!authorizations.Any() && await _applicationManager.HasConsentTypeAsync(application, ConsentTypes.External))
            {
                return Forbid(
                    authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                    properties: new AuthenticationProperties(new Dictionary<string, string?>
                    {
                        [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.ConsentRequired,
                        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
                            "The logged in user is not allowed to access this client application."
                    }));
            }

            // Create the claims-based identity that will be used by OpenIddict to generate tokens.
            var identity = new ClaimsIdentity(
                authenticationType: TokenValidationParameters.DefaultAuthenticationType,
                nameType: Claims.Name,
                roleType: Claims.Role);

            // Add the claims that will be persisted in the tokens.
            if (pscopes.Contains(OpenIddictConstants.Scopes.Email))
            {
                identity.SetClaim(Claims.Email, await _userManager.GetEmailAsync(user));
            }
            if (pscopes.Contains(OpenIddictConstants.Scopes.Profile))
            {
                identity.SetClaim(Claims.Subject, await _userManager.GetUserIdAsync(user))
                    .SetClaim(Claims.Name, await _userManager.GetUserNameAsync(user));
            }
            if (pscopes.Contains(OpenIddictConstants.Scopes.Roles))
            {
                identity.SetClaims(Claims.Role, (await _userManager.GetRolesAsync(user)).ToImmutableArray());
            }

            // Note: in this sample, the granted scopes match the requested scope
            // but you may want to allow the user to uncheck specific scopes.
            // For that, simply restrict the list of scopes before calling SetScopes.
            identity.SetScopes(pscopes);

            var lstres = await _scopeManager.ListResourcesAsync(pscopes).ToListAsync();
            if ((uscopes != null) && (lstres != null))
            {
                lstres = uscopes.OidcAudiences.Intersect(lstres).ToList();
            }
            identity.SetResources(lstres);

            // Automatically create a permanent authorization to avoid requiring explicit consent
            // for future authorization or token requests containing the same scopes.
            var authorization = authorizations.LastOrDefault();
            authorization ??= await _authorizationManager.CreateAsync(
                identity: identity,
                subject: await _userManager.GetUserIdAsync(user),
                client: appId,
                type: AuthorizationTypes.Permanent,
                scopes: pscopes);
            identity.SetAuthorizationId(await _authorizationManager.GetIdAsync(authorization));
            identity.SetDestinations(GetDestinations);

            // Returning a SignInResult will ask OpenIddict to issue the appropriate access/identity tokens.
            return SignIn(new ClaimsPrincipal(identity), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }
        #endregion

        #region Logout support for interactive flows like code and implicit
        // Note: the logout action is only useful when implementing interactive
        // flows like the authorization code flow or the implicit flow.

        [HttpGet("~/connect/logout")]
        public IActionResult Logout() => View();

        [ActionName(nameof(Logout)), HttpPost("~/connect/logout"), ValidateAntiForgeryToken]
        [FormValueRequired("submit.Accept")]
        public async Task<IActionResult> LogoutPost()
        {
            // Ask ASP.NET Core Identity to delete the local and external cookies created
            // when the user agent is redirected from the external identity provider
            // after a successful authentication flow (e.g Google or Facebook).
            await _signInManager.SignOutAsync();

            // Returning a SignOutResult will ask OpenIddict to redirect the user agent
            // to the post_logout_redirect_uri specified by the client application or to
            // the RedirectUri specified in the authentication properties if none was set.
            return SignOut(
                authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                properties: new AuthenticationProperties
                {
                    RedirectUri = "~/"
                });
        }

        [ActionName(nameof(Logout)), HttpPost("~/connect/logout"), ValidateAntiForgeryToken]
        [FormValueRequired("submit.Deny")]
        public IActionResult LogoutDeny()
        {
            var response = HttpContext.GetOpenIddictServerResponse();
            if (response != null)
            {
                return View("Error", new OidcErrorDto
                {
                    Error = response.Error,
                    ErrorDescription = response.ErrorDescription
                });
            }

            var request = HttpContext.GetOpenIddictServerRequest();
            if (request == null)
            {
                return NotFound();
            }

            string respUrl = "~/";
            if(!string.IsNullOrEmpty(request.PostLogoutRedirectUri))
            {
                // remove "signout-callback-oidc"-tail
                respUrl = request.PostLogoutRedirectUri;
                if (respUrl.EndsWith('/'))
                    respUrl += "../";
                else
                    respUrl += "/../";
            }
            return Redirect(respUrl);
        }




        #endregion

        #region Device flow
        // Note: to support the device flow, you must provide your own verification endpoint action:
        [Authorize, HttpGet("~/connect/verify"), IgnoreAntiforgeryToken]
        public async Task<IActionResult> Verify()
        {
            var request = HttpContext.GetOpenIddictServerRequest() ??
                throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

            // If the user code was not specified in the query string (e.g as part of the verification_uri_complete),
            // render a form to ask the user to enter the user code manually (non-digit chars are automatically ignored).
            if (string.IsNullOrEmpty(request.UserCode))
            {
                return View(new VerifyViewDto());
            }

            // Retrieve the claims principal associated with the user code.
            var result = await HttpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            if (result.Succeeded)
            {
                string appId = result.Principal.GetClaim(Claims.ClientId) ??
                    throw new InvalidOperationException("Details concerning the calling client application cannot be found.");
                // Retrieve the application details from the database using the client_id stored in the principal.
                var application = await _applicationManager.FindByClientIdAsync(appId) ??
                    throw new InvalidOperationException("Details concerning the calling client application cannot be found.");

                // Render a form asking the user to confirm the authorization demand.
                var pscopes = result.Principal.GetScopes();

                // Retrieve the profile of the logged in user.
                var user = await _userManager.GetUserAsync(User) ??
                    throw new InvalidOperationException("The user details cannot be retrieved.");
                OidcScopeADto? uscopes = null;
                if (AnalizeUserScopes || AnalizeGroupScopes)
                {
                    uscopes = await GetUserScopesAsync(user, appId);
                    pscopes = uscopes.OidcScopes.Intersect(pscopes).ToImmutableArray();
                }

                var ScpWithRes = await PrepareScopesToDisplay(pscopes, uscopes);
                ViewBag.ScpWithRes = ScpWithRes;
                return View(new VerifyViewDto
                {
                    ApplicationName = await _applicationManager.GetLocalizedDisplayNameAsync(application),
                    Scope = string.Join(" ", pscopes),
                    UserCode = request.UserCode
                });
            }

            // Redisplay the form when the user code is not valid.
            return View(new VerifyViewDto
            {
                Error = Errors.InvalidToken,
                ErrorDescription = "The specified user code is not valid. Please make sure you typed it correctly."
            });
        }

        [Authorize, FormValueRequired("submit.Accept")]
        [HttpPost("~/connect/verify"), ValidateAntiForgeryToken]
        public async Task<IActionResult> VerifyAccept(string user_code, [Bind("ApplicationName", "Scope", "UserCode", "ScopesToAuthorize")] VerifyViewDto verifyViewDto)
        {
            // Retrieve the profile of the logged in user.
            var user = await _userManager.GetUserAsync(User) ??
                throw new InvalidOperationException("The user details cannot be retrieved.");

            // Retrieve the claims principal associated with the user code.
            var result = await HttpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            if (result.Succeeded)
            {
                // Create the claims-based identity that will be used by OpenIddict to generate tokens.
                var identity = new System.Security.Claims.ClaimsIdentity(
                    authenticationType: TokenValidationParameters.DefaultAuthenticationType,
                    nameType: Claims.Name,
                    roleType: Claims.Role);

                // Add the claims that will be persisted in the tokens.
                var pscopes = (result.Principal.GetScopes().Intersect(verifyViewDto.ScopesToAuthorize)).ToImmutableArray();
                if(pscopes.Contains(OpenIddictConstants.Scopes.Email))
                {
                    identity.SetClaim(Claims.Email, await _userManager.GetEmailAsync(user));
                }
                if (pscopes.Contains(OpenIddictConstants.Scopes.Profile))
                {
                    identity.SetClaim(Claims.Subject, await _userManager.GetUserIdAsync(user))
                        .SetClaim(Claims.Name, await _userManager.GetUserNameAsync(user));
                }
                if (pscopes.Contains(OpenIddictConstants.Scopes.Roles))
                {
                    identity.SetClaims(Claims.Role, (await _userManager.GetRolesAsync(user)).ToImmutableArray());
                }


                // Note: in this sample, the granted scopes match the requested scope
                // but you may want to allow the user to uncheck specific scopes.
                // For that, simply restrict the list of scopes before calling SetScopes.
                identity.SetScopes(pscopes);
                var lstres = await _scopeManager.ListResourcesAsync(pscopes).ToListAsync();
                if ((AnalizeUserScopes || AnalizeGroupScopes) && (lstres != null)) 
                {
                    string appId = result.Principal.GetClaim(Claims.ClientId) ??
                        throw new InvalidOperationException("Details concerning the calling client application cannot be found.");
                    var uscopes = await GetUserScopesAsync(user, appId);
                    if (uscopes != null)
                    {
                        lstres = uscopes.OidcAudiences.Intersect(lstres).ToList();
                    }
                }

                identity.SetResources(lstres);
                identity.SetDestinations(GetDestinations);

                var properties = new AuthenticationProperties
                {
                    // This property points to the address OpenIddict will automatically
                    // redirect the user to after validating the authorization demand.
                    RedirectUri = "/"
                };

                return SignIn(new ClaimsPrincipal(identity), properties, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            }

            // Redisplay the form when the user code is not valid.
            return View("verify", new VerifyViewDto
            {
                Error = Errors.InvalidToken,
                ErrorDescription = "The specified user code is not valid. Please make sure you typed it correctly."
            });
        }

        [Authorize, FormValueRequired("submit.Deny")]
        [HttpPost("~/connect/verify"), ValidateAntiForgeryToken]
        // Notify OpenIddict that the authorization grant has been denied by the resource owner.
        public IActionResult VerifyDeny() => Forbid(
            authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
            properties: new AuthenticationProperties()
            {
                // This property points to the address OpenIddict will automatically
                // redirect the user to after rejecting the authorization demand.
                RedirectUri = "/"
            });
        #endregion


        #region Password, authorization code, device and refresh token flows
        // Note: to support non-interactive flows like password,
        // you must provide your own token endpoint action:

        [HttpPost("~/connect/token"), IgnoreAntiforgeryToken, Produces("application/json")]
        public async Task<IActionResult> Exchange()
        {
            var request = HttpContext.GetOpenIddictServerRequest() ??
                throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

            if (request.IsPasswordGrantType())
            {
                var user = await _userManager.FindByNameAsync(request.Username);
                if (user is null)
                {
                    return Forbid(
                        authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                        properties: new AuthenticationProperties(new Dictionary<string, string?>
                        {
                            [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                            [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "The username/password couple is invalid."
                        }));
                }

                // Validate the username/password parameters and ensure the account is not locked out.
                var result = await _signInManager.CheckPasswordSignInAsync(user, request.Password, lockoutOnFailure: true);
                if (!result.Succeeded)
                {
                    return Forbid(
                        authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                        properties: new AuthenticationProperties(new Dictionary<string, string?>
                        {
                            [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                            [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "The username/password couple is invalid."
                        }));
                }

                string clientId = request.ClientId ??
                    throw new InvalidOperationException("Details concerning the calling client application cannot be found.");
                var application = await _applicationManager.FindByClientIdAsync(clientId) ??
                    throw new InvalidOperationException("Details concerning the calling client application cannot be found.");
                string appId = await _applicationManager.GetIdAsync(application) ??
                    throw new InvalidOperationException("Details concerning the calling client application cannot be found.");

                var pscopes = request.GetScopes();

                OidcScopeADto? uscopes = null;
                if (AnalizeUserScopes || AnalizeGroupScopes)
                {
                    uscopes = await GetUserScopesAsync(user, clientId);
                    if (uscopes != null)
                        pscopes = uscopes.OidcScopes.Intersect(pscopes).ToImmutableArray();
                }


                // Create the claims-based identity that will be used by OpenIddict to generate tokens.
                var identity = new ClaimsIdentity(
                    authenticationType: TokenValidationParameters.DefaultAuthenticationType,
                    nameType: Claims.Name,
                    roleType: Claims.Role);

                // Add the claims that will be persisted in the tokens.
                identity.SetClaim(Claims.Subject, await _userManager.GetUserIdAsync(user))
                        .SetClaim(Claims.Email, await _userManager.GetEmailAsync(user))
                        .SetClaim(Claims.Name, await _userManager.GetUserNameAsync(user))
                        .SetClaims(Claims.Role, (await _userManager.GetRolesAsync(user)).ToImmutableArray());

                // Note: in this sample, the granted scopes match the requested scope
                // but you may want to allow the user to uncheck specific scopes.
                // For that, simply restrict the list of scopes before calling SetScopes.
                identity.SetScopes(pscopes);
                var lstres = await _scopeManager.ListResourcesAsync(pscopes).ToListAsync();
                if ((uscopes != null) && (lstres != null))
                {
                    if (uscopes != null)
                    {
                        lstres = uscopes.OidcAudiences.Intersect(lstres).ToList();
                    }
                }

                identity.SetResources(lstres);
                identity.SetDestinations(GetDestinations);

                // Returning a SignInResult will ask OpenIddict to issue the appropriate access/identity tokens.
                return SignIn(new ClaimsPrincipal(identity), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            }

            else if (request.IsAuthorizationCodeGrantType() || request.IsDeviceCodeGrantType() || request.IsRefreshTokenGrantType())
            {
                // Retrieve the claims principal stored in the authorization code/device code/refresh token.
                var result = await HttpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

                // Retrieve the user profile corresponding to the authorization code/refresh token.
                var user = await _userManager.FindByIdAsync(result.Principal!.GetClaim(Claims.Subject));
                if (user is null)
                {
                    return Forbid(
                        authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                        properties: new AuthenticationProperties(new Dictionary<string, string?>
                        {
                            [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                            [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "The token is no longer valid."
                        }));
                }

                // Ensure the user is still allowed to sign in.
                if (!await _signInManager.CanSignInAsync(user))
                {
                    return Forbid(
                        authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                        properties: new AuthenticationProperties(new Dictionary<string, string?>
                        {
                            [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                            [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "The user is no longer allowed to sign in."
                        }));
                }

                var identity = new ClaimsIdentity(result.Principal!.Claims,
                    authenticationType: TokenValidationParameters.DefaultAuthenticationType,
                    nameType: Claims.Name,
                    roleType: Claims.Role);

                // Override the user claims present in the principal in case they
                // changed since the authorization code/refresh token was issued.
                identity.SetClaim(Claims.Subject, await _userManager.GetUserIdAsync(user))
                        .SetClaim(Claims.Email, await _userManager.GetEmailAsync(user))
                        .SetClaim(Claims.Name, await _userManager.GetUserNameAsync(user))
                        .SetClaims(Claims.Role, (await _userManager.GetRolesAsync(user)).ToImmutableArray());

                identity.SetDestinations(GetDestinations);

                // Returning a SignInResult will ask OpenIddict to issue the appropriate access/identity tokens.
                return SignIn(new ClaimsPrincipal(identity), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            }
            else if (request.IsClientCredentialsGrantType())
            {
                // Note: the client credentials are automatically validated by OpenIddict:
                // if client_id or client_secret are invalid, this action won't be invoked.

                var application = await _applicationManager.FindByClientIdAsync(request.ClientId!);
                if (application == null)
                {
                    throw new InvalidOperationException("The application details cannot be found in the database.");
                }

                // Create the claims-based identity that will be used by OpenIddict to generate tokens.
                var identity = new ClaimsIdentity(
                    authenticationType: TokenValidationParameters.DefaultAuthenticationType,
                    nameType: Claims.Name,
                    roleType: Claims.Role);

                // Add the claims that will be persisted in the tokens (use the client_id as the subject identifier).
                identity.SetClaim(Claims.Subject, await _applicationManager.GetClientIdAsync(application));
                identity.SetClaim(Claims.Name, await _applicationManager.GetDisplayNameAsync(application));

                // Note: In the original OAuth 2.0 specification, the client credentials grant
                // doesn't return an identity token, which is an OpenID Connect concept.
                //
                // As a non-standardized extension, OpenIddict allows returning an id_token
                // to convey information about the client application when the "openid" scope
                // is granted (i.e specified when calling principal.SetScopes()). When the "openid"
                // scope is not explicitly set, no identity token is returned to the client application.

                // Set the list of scopes granted to the client application in access_token.
                identity.SetScopes(request.GetScopes());
                identity.SetResources(await _scopeManager.ListResourcesAsync(identity.GetScopes()).ToListAsync());
                identity.SetDestinations(GetDestinations);

                return SignIn(new ClaimsPrincipal(identity), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            }

            throw new InvalidOperationException("The specified grant type is not supported.");
        }
        #endregion

        #region Helper methods
        protected virtual async Task<List<(string, string?, string?, List<string>)>> PrepareScopesToDisplay(IList<string>? pscopes, OidcScopeADto? uscopes = null)
        {
            List<(string, string?, string?, List<string>)> ScpWithRes = new();
            if (pscopes != null)
            {
                foreach (var pscope in pscopes)
                {
                    Object? oscp = await _scopeManager.FindByNameAsync(pscope);
                    if (oscp != null)
                    {
                        string? ldispname = await _scopeManager.GetLocalizedDisplayNameAsync(oscp);
                        string? ldescr = await _scopeManager.GetLocalizedDescriptionAsync(oscp);
                        (string, string?, string?, List<string>) itm = (pscope, ldispname, ldescr, new List<string>());
                        if(! ((pscope == "openid") || (pscope == "offline_access")) ) {
                            foreach (var resource in await _scopeManager.GetResourcesAsync(oscp))
                            {
                                if (uscopes != null)
                                {
                                    if (uscopes.OidcAudiences.Contains(resource))
                                    {
                                        itm.Item4.Add(resource);
                                    }
                                }
                                else
                                {
                                    itm.Item4.Add(resource);
                                }
                            }
                        }
                        ScpWithRes.Add(itm);
                    }
                }
            }
            return ScpWithRes;
        }
        protected virtual async Task<OidcScopeADto> GetUserScopesAsync(OidcIdentityUser user, string appId)
        {
            string userId = user.Id;
            OidcScopeADto rslt = new ();
            string prfx = _claimprefixval + appId;
/*
            if (AnalizeUserClaims)
            {
                var uclaims = (await _userManager.GetClaimsAsync(user)).Where(c => c.Type.StartsWith(prfx) && (!string.IsNullOrEmpty(c.Value))).ToArray();
                if (uclaims != null)
                {
                    foreach (var claim in uclaims)
                    {
                        if (claim.Value.StartsWith(Prefixes.Scope))
                        {
                            var scps = claim.Value[Prefixes.Scope.Length..].Trim().Split(Separators.Space, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
                            rslt.UnionWith(scps);
                        }
                    }
                }
            }
            if (AnalizeRoleClaims)
            {
                var roleNames = (await _userManager.GetRolesAsync(user)).Where(r => r.StartsWith(_roleprefixval)).ToArray();
                if (roleNames.Length > 0)
                {
                    var roles = await _roleManager.Roles.Where(r => roleNames.Contains(r.Name)).ToListAsync();
                    foreach (var role in roles)
                    {
                        var rclaims = (await _roleManager.GetClaimsAsync(role)).Where(c => c.Type.StartsWith(prfx) && (!string.IsNullOrEmpty(c.Value))).ToArray();
                        if (rclaims != null)
                        {
                            foreach (var claim in rclaims)
                            {
                                if (claim.Value.StartsWith(Prefixes.Scope))
                                {
                                    var scps = claim.Value[Prefixes.Scope.Length..].Trim().Split(Separators.Space, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
                                    rslt.UnionWith(scps);
                                }
                            }
                        }
                    }
                }
            }
*/
            if (AnalizeUserScopes)
            {
                OidcScopeDto? uscpDto = (await _context.OidcUserScopes.Where(s => s.OidcUserId == userId && s.OidcAppName == appId)
                    .Select(itm => new OidcScopeDto() {
                        OidcScopes = itm.OidcScopes,
                        OidcAudiences = itm.OidcAudiences,
                    }
                    ).FirstOrDefaultAsync());
                if (uscpDto != null)
                {
                    if (!string.IsNullOrEmpty(uscpDto.OidcScopes))
                    {
                        var tuscp = uscpDto.OidcScopes.Trim().Split(Separators.Space, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
                        rslt.OidcScopes.UnionWith(tuscp);
                    }
                    if (!string.IsNullOrEmpty(uscpDto.OidcAudiences))
                    {
                        var tuscp = uscpDto.OidcAudiences.Trim().Split(Separators.Space, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
                        rslt.OidcAudiences.UnionWith(tuscp);
                    }
                }
            }
            if (AnalizeGroupScopes)
            {
                // var gscp = await _context.OidcGroupScopes.Where(g=> (g.Group.UserGroups.Any(gu=>gu.OidcUserId == userId)) && g.OidcAppName == appId).Select(gu => gu.OidcScopes).ToListAsync();
                List<OidcScopeDto> gscp = await (from ug in _context.OidcUserGroups.Where(ugi => ugi.OidcUserId == userId)
                                  join gs in _context.OidcGroupScopes
                                  on ug.OidcGroupId equals gs.OidcGroupId
                                  where gs.OidcAppName == appId
                                  select (new OidcScopeDto { OidcScopes = gs.OidcScopes, OidcAudiences = gs.OidcAudiences })).ToListAsync();
                if (gscp != null)
                {
                    foreach(var sgscp in gscp)
                    {
                        if (!string.IsNullOrEmpty(sgscp.OidcScopes))
                        {
                            var tgscp = sgscp.OidcScopes.Trim().Split(Separators.Space, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
                            rslt.OidcScopes.UnionWith(tgscp);
                        }
                        if (!string.IsNullOrEmpty(sgscp.OidcAudiences))
                        {
                            var tgscp = sgscp.OidcAudiences.Trim().Split(Separators.Space, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
                            rslt.OidcAudiences.UnionWith(tgscp);
                        }
                    }
                }
            }

            return rslt;
        }
        private static IEnumerable<string> GetDestinations(Claim claim)
        {
            // Note: by default, claims are NOT automatically included in the access and identity tokens.
            // To allow OpenIddict to serialize them, you must attach them a destination, that specifies
            // whether they should be included in access tokens, in identity tokens or in both.

            switch (claim.Type)
            {
                // If the claim already includes destinations (set before this helper is called), flow them as-is.
                case string when claim.GetDestinations() is { IsDefaultOrEmpty: false } destinations:
                    return destinations;

                // Never include the security stamp in the access and identity tokens, as it's a secret value.
                case "AspNet.Identity.SecurityStamp":
                    return Enumerable.Empty<string>();

                // Only add the claim to the id_token if the corresponding scope was granted.
                // The other claims will only be added to the access_token.
                //case OpenIdConstants.Claims.EntityType:
                case Claims.Name when (claim.Subject != null) && claim.Subject.HasScope(OpenIddictConstants.Scopes.Profile):
                case Claims.Email when (claim.Subject != null) && claim.Subject.HasScope(OpenIddictConstants.Scopes.Email):
                case Claims.Role when (claim.Subject != null) && claim.Subject.HasScope(OpenIddictConstants.Scopes.Roles):
                    return new[]
                    {
                        Destinations.AccessToken,
                        Destinations.IdentityToken
                    };
                default: return new[] { Destinations.AccessToken };
            }
        }
        #endregion
    }
}
