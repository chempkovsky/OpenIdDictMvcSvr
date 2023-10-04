using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.EntityFrameworkCore;
using OpenIdDictMvcContext.Data;
using OpenIdDictMvcLib.Dto;
using OpenIddict.Abstractions;
using Microsoft.Extensions.Localization;
using static OpenIddict.Abstractions.OpenIddictConstants;
using System.Text;
using OpenIdDictMvcLib.Helpers;
using OpenIdDictMvcLib.Localizers;
using System.Globalization;
using System.Text.RegularExpressions;
using Microsoft.EntityFrameworkCore.Metadata.Internal;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Logging;

namespace OpenIdDictMvcLib.Controllers
{
    [Authorize]
    public class OpenIddictAppsController : Controller
    {
        private readonly ApplicationDbContext _context;
        private readonly IOpenIddictApplicationManager _applicationManager;
        private readonly IStringLocalizer<OpenIddictAppLocalizerResource> _sharedLocalizer;
        private readonly ILogger<OpenIddictApplicationDescriptorDto> _logger;

        public OpenIddictAppsController(ApplicationDbContext context,
            IOpenIddictApplicationManager applicationManager,
            ILogger<OpenIddictApplicationDescriptorDto> logger,
            IStringLocalizer<OpenIddictAppLocalizerResource> SharedLocalizer)
        {
            _context = context;
            _logger = logger;
            _applicationManager = applicationManager;
            _sharedLocalizer = SharedLocalizer;
        }

        // GET: OpenIddictApps
        public async Task<IActionResult> Index(string? searchby = null, string? searchstr = null, int? currpg = null)
        {
            PageDto pager = new() { PageSize = 10 };
            if (currpg.HasValue)
            {
                pager.CurrentPage = currpg.Value;
            }
            else
            {
                pager.CurrentPage = 1;
            }
            int SearchById = 0;
            if (!string.IsNullOrEmpty(searchby))
            {
                switch (searchby)
                {
                    case "1":
                        SearchById = 1;
                        break;
                }
            }
            ViewBag.SearchById = SearchById.ToString();
            ViewBag.SearchBy = new List<SelectListItem>() {
                new SelectListItem(){ Text = _sharedLocalizer["Filter by Record Id"], Value = "0", Selected = SearchById == 0 },
                new SelectListItem(){ Text = _sharedLocalizer["Filter by App Id"], Value = "1", Selected = SearchById == 1 },
            };
            if (!string.IsNullOrEmpty(searchstr))
            {
                ViewBag.SearchString = searchstr;
                Object? app = SearchById switch
                {
                    1 => app = (await _applicationManager.FindByClientIdAsync(searchstr)),
                    _ => app = (await _applicationManager.FindByIdAsync(searchstr))
                };
                List<OpenIddictAppDto> rslt = new();
                if (app != null)
                {
                    rslt.Add(new OpenIddictAppDto()
                    {
                        Id = await _applicationManager.GetIdAsync(app),
                        ClientId = await _applicationManager.GetClientIdAsync(app),
                        DisplayName = await _applicationManager.GetDisplayNameAsync(app),
                        ConsentType = await _applicationManager.GetConsentTypeAsync(app),
                        ClientType = await _applicationManager.GetClientTypeAsync(app),
                    });
                }
                pager.PageCount = 0;
                pager.PrintFrom = 1;
                pager.PrintTo = 0;
                ViewBag.Pager = pager;
                pager.CurrentPage = 1;
                return View(rslt);
            }
            else
            {
                ViewBag.SearchString = "";
            }

            var dbst = _context.Set<OidcApplication>();
            if (dbst == null)
            {
                return Problem(_sharedLocalizer["Entity set 'ApplicationDbContext.OpenIddictEntityFrameworkCoreApplication' is null."]);
            }
            var query = dbst.AsNoTracking();
            int total = (int)await _applicationManager.CountAsync();
            pager.PageCount = total / pager.PageSize;
            if (pager.PageCount * pager.PageSize < total) pager.PageCount++;
            if ((pager.CurrentPage > pager.PageCount) || (pager.CurrentPage < 1)) pager.CurrentPage = 1;
            pager.PrintFrom = pager.CurrentPage - 2;
            if (pager.PrintFrom < 1) pager.PrintFrom = 1;
            pager.PrintTo = pager.PrintFrom + 5;
            if (pager.PrintTo > pager.PageCount) pager.PrintTo = pager.PageCount;
            if (total < 1)
            {
                ViewBag.Pager = pager;
                return View(new List<OpenIddictAppDto>());
            }
            if (pager.CurrentPage > 1)
            {

                query = query.OrderBy(a => a.Id).Skip((pager.CurrentPage - 1) * pager.PageSize);
            }
            ViewBag.Pager = pager;
            return View(await query.AsNoTracking().Take(pager.PageSize).Select(itm => new OpenIddictAppDto()
            {
                Id = itm.Id,
                ClientId = itm.ClientId,
                ConsentType = itm.ConsentType,
                DisplayName = itm.DisplayName,
                ClientType = itm.Type
            }).ToListAsync());
        }

        internal List<SelectListItem> GetConsentTypesList(string sel)
        {
            return new List<SelectListItem>() {
                new SelectListItem { Value = ConsentTypes.Explicit, Text = _sharedLocalizer[ConsentTypes.Explicit], Selected = ConsentTypes.Explicit == sel  },
                new SelectListItem { Value = ConsentTypes.External, Text = _sharedLocalizer[ConsentTypes.External], Selected = ConsentTypes.External == sel },
                new SelectListItem { Value = ConsentTypes.Implicit, Text = _sharedLocalizer[ConsentTypes.Implicit], Selected = ConsentTypes.Implicit == sel },
                new SelectListItem { Value = ConsentTypes.Systematic, Text = _sharedLocalizer[ConsentTypes.Systematic], Selected = ConsentTypes.Systematic == sel },
            };
        }
        internal List<SelectListItem> GetClientTypesList(string sel)
        {
            return new List<SelectListItem>() {
                new SelectListItem { Value = ClientTypes.Confidential, Text = _sharedLocalizer[ClientTypes.Confidential], Selected = ClientTypes.Confidential == sel },
                new SelectListItem { Value = ClientTypes.Public, Text = _sharedLocalizer[ClientTypes.Public], Selected = ClientTypes.Public == sel },
            };

        }

        internal MultiSelectList GetPermissionsList(string[] selected)
        {
            string ep = _sharedLocalizer["Endpoints"];
            string gt = _sharedLocalizer["GrantTypes"];
            string rp = _sharedLocalizer["ResponseTypes"];
            string scp = _sharedLocalizer["Scopes"];

            var lst = new List<object>()
            {
                new  { Value = Permissions.Endpoints.Authorization, Text = _sharedLocalizer["Authorization=" + Permissions.Endpoints.Authorization], Group=ep  },
                new  { Value = Permissions.Endpoints.Device, Text = _sharedLocalizer["Device="+Permissions.Endpoints.Device], Group=ep  },
                new  { Value = Permissions.Endpoints.Introspection, Text = _sharedLocalizer["Introspection="+ Permissions.Endpoints.Introspection], Group=ep  },
                new  { Value = Permissions.Endpoints.Logout, Text = _sharedLocalizer["Logout="+Permissions.Endpoints.Logout], Group=ep  },
                new  { Value = Permissions.Endpoints.Revocation, Text = _sharedLocalizer["Revocation="+Permissions.Endpoints.Revocation], Group=ep  },
                new  { Value = Permissions.Endpoints.Token, Text = _sharedLocalizer["Token="+Permissions.Endpoints.Token], Group=ep  },

                new  { Value = Permissions.GrantTypes.AuthorizationCode, Text = _sharedLocalizer["Authorization code="+Permissions.GrantTypes.AuthorizationCode], Group=gt },
                new  { Value = Permissions.GrantTypes.ClientCredentials, Text = _sharedLocalizer["Client credentials="+Permissions.GrantTypes.ClientCredentials], Group=gt },
                new  { Value = Permissions.GrantTypes.DeviceCode, Text = _sharedLocalizer["Device Code="+Permissions.GrantTypes.DeviceCode], Group=gt },
                new  { Value = Permissions.GrantTypes.Implicit, Text = _sharedLocalizer["Implicit="+Permissions.GrantTypes.Implicit], Group=gt },
                new  { Value = Permissions.GrantTypes.Password, Text = _sharedLocalizer["Password="+Permissions.GrantTypes.Password], Group=gt },
                new  { Value = Permissions.GrantTypes.RefreshToken, Text = _sharedLocalizer["Refresh token="+Permissions.GrantTypes.RefreshToken], Group=gt },

                new  { Value = Permissions.ResponseTypes.Code, Text = _sharedLocalizer["code="+Permissions.ResponseTypes.Code], Group=rp },
                new  { Value = Permissions.ResponseTypes.CodeIdToken, Text = _sharedLocalizer["code id_token="+Permissions.ResponseTypes.CodeIdToken], Group=rp },
                new  { Value = Permissions.ResponseTypes.CodeIdTokenToken, Text = _sharedLocalizer["code id_token token="+Permissions.ResponseTypes.CodeIdTokenToken], Group=rp },
                new  { Value = Permissions.ResponseTypes.CodeToken, Text = _sharedLocalizer["code token="+Permissions.ResponseTypes.CodeToken], Group=rp },
                new  { Value = Permissions.ResponseTypes.IdToken, Text = _sharedLocalizer["id_token="+Permissions.ResponseTypes.IdToken], Group=rp },
                new  { Value = Permissions.ResponseTypes.IdTokenToken, Text = _sharedLocalizer["id_token token="+Permissions.ResponseTypes.IdTokenToken], Group=rp },
                new  { Value = Permissions.ResponseTypes.None, Text = _sharedLocalizer["none="+Permissions.ResponseTypes.None], Group=rp },
                new  { Value = Permissions.ResponseTypes.Token, Text = _sharedLocalizer["token="+Permissions.ResponseTypes.Token], Group=rp },

                new  { Value = Permissions.Scopes.Address, Text = _sharedLocalizer["address="+Permissions.Scopes.Address], Group=scp },
                new  { Value = Permissions.Scopes.Email, Text = _sharedLocalizer["email="+Permissions.Scopes.Email], Group=scp },
                new  { Value = Permissions.Scopes.Phone, Text = _sharedLocalizer["phone="+Permissions.Scopes.Phone], Group=scp },
                new  { Value = Permissions.Scopes.Profile, Text = _sharedLocalizer["profile=" + Permissions.Scopes.Profile], Group=scp },
                new  { Value = Permissions.Scopes.Roles, Text = _sharedLocalizer["roles=" + Permissions.Scopes.Roles], Group=scp },
            };


            return new MultiSelectList(lst, "Value", "Text", selected, "Group");
        }

        internal MultiSelectList GetRequirementsList(string[] selected)
        {
            var lst = new List<Object>()
            {
                new  { Value = Requirements.Features.ProofKeyForCodeExchange, Text = _sharedLocalizer["ProofKeyForCodeExchange=" + Requirements.Features.ProofKeyForCodeExchange]},
            };

            return new MultiSelectList(lst, "Value", "Text", selected);
        }

        // GET: OpenIddictApps/Create
        public IActionResult Create()
        {
            ViewBag.ConsentTypesList = GetConsentTypesList("");
            ViewBag.ClientTypesList = GetClientTypesList("");
            ViewBag.PermissionsList = GetPermissionsList(Array.Empty<string>());
            ViewBag.RequirementsList = GetRequirementsList(Array.Empty<string>());
            // ViewBag.CustomPermissions = new string[] { };
            // ViewBag.RedirectUris = new Uri[] { new Uri("/x.x.com/", UriKind.RelativeOrAbsolute), new Uri("./x.x.by/", UriKind.RelativeOrAbsolute) };
            // ViewBag.PostLogoutRedirectUris = new Uri[] { new Uri("/x.x.com/", UriKind.RelativeOrAbsolute), new Uri("./x.x.by/", UriKind.RelativeOrAbsolute) };
            // OpenIddictApplicationDescriptorDto vv = new OpenIddictApplicationDescriptorDto() { CustomPermissions = new List<string> { "aaa", "bbb"} };
            return View();
        }

        internal void CheckCollection(OpenIddictApplicationDescriptorDto descriptorDto)
        {
            bool errNotAdded = true;
            if (descriptorDto.CustomPermissions != null)
            {
                foreach (var permission in descriptorDto.CustomPermissions)
                {
                    if (string.IsNullOrEmpty(permission))
                    {
                        if (errNotAdded)
                        {
                            ModelState.AddModelError("CustomPermissions", _sharedLocalizer["Not all Custom Permissions UIs are populated with data."]);
                            errNotAdded = false;
                        }
                    }
                }
            }
            errNotAdded = true;
            if (descriptorDto.PostLogoutRedirectUris != null)
            {
                foreach (var postLogoutRedirectUri in descriptorDto.PostLogoutRedirectUris)
                {
                    if (postLogoutRedirectUri == null)
                    {
                        if (errNotAdded)
                        {
                            ModelState.AddModelError("PostLogoutRedirectUris", _sharedLocalizer["Not all Post Logout Redirect Uris UIs are populated with data."]);
                            errNotAdded = false;
                        }
                    }
                    else if (string.IsNullOrEmpty(postLogoutRedirectUri)) // .AbsoluteUri
                    {
                        if (errNotAdded)
                        {
                            ModelState.AddModelError("PostLogoutRedirectUris", _sharedLocalizer["Not all Post Logout Redirect Uris UIs are populated with data."]);
                            errNotAdded = false;
                        }
                    }
                }
            }
            errNotAdded = true;
            if (descriptorDto.RedirectUris != null)
            {
                foreach (var redirectUri in descriptorDto.RedirectUris)
                {
                    if (redirectUri == null)
                    {
                        if (errNotAdded)
                        {
                            ModelState.AddModelError("RedirectUris", _sharedLocalizer["Not all Redirect Uris UIs are populated with data."]);
                            errNotAdded = false;
                        }
                    }
                    else if (string.IsNullOrEmpty(redirectUri)) // .AbsoluteUri
                    {
                        if (errNotAdded)
                        {
                            ModelState.AddModelError("RedirectUris", _sharedLocalizer["Not all Redirect Uris UIs are populated with data."]);
                            errNotAdded = false;
                        }
                    }
                }
            }
            errNotAdded = true;
            if (descriptorDto.DisplayNames != null)
            {
                if (descriptorDto.DisplayNames.Count > 0)
                {
                    foreach (var dn in descriptorDto.DisplayNames)
                    {
                        if (string.IsNullOrEmpty(dn.Key) || string.IsNullOrEmpty(dn.Value))
                        {
                            if (errNotAdded)
                            {
                                ModelState.AddModelError("DisplayNames", _sharedLocalizer["Not all Display Names UIs are populated with data."]);
                                errNotAdded = false;
                            }
                        }
                    }
                }
            }

        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create([Bind("ClientId,ClientSecret,DisplayName,ConsentType,ClientType,Requirements,RedirectUris,PostLogoutRedirectUris,Permissions,CustomPermissions,DisplayNames")] OpenIddictApplicationDescriptorDto descriptorDto)
        {
            if (ModelState.IsValid)
            {
                CheckCollection(descriptorDto);
                if (ModelState.IsValid)
                {
                    OpenIddictApplicationDescriptor descriptor = new()
                    {
                        ClientId = descriptorDto.ClientId,
                        ClientSecret = descriptorDto.ClientSecret,
                        DisplayName = descriptorDto.DisplayName,
                        ConsentType = descriptorDto.ConsentType,
                        Type = descriptorDto.ClientType
                    };
                    if (descriptorDto.Permissions != null)
                    {
                        foreach (var permission in descriptorDto.Permissions)
                        {
                            descriptor.Permissions.Add(permission);
                        }
                    }
                    if (descriptorDto.CustomPermissions != null)
                    {
                        foreach (var permission in descriptorDto.CustomPermissions)
                        {
                            descriptor.Permissions.Add(permission);
                        }
                    }
                    if (descriptorDto.PostLogoutRedirectUris != null)
                    {
                        foreach (var postLogoutRedirectUri in descriptorDto.PostLogoutRedirectUris)
                        {
                            if (Uri.TryCreate(postLogoutRedirectUri, UriKind.RelativeOrAbsolute, out Uri? luri))
                            {
                                if (luri != null) descriptor.PostLogoutRedirectUris.Add(luri);
                            }
                            else
                            {
                                ModelState.AddModelError("PostLogoutRedirectUri", _sharedLocalizer["Not all Post Logout Redirect Uri UIs are populated with correct data."]);
                            }
                        }
                    }
                    if (descriptorDto.RedirectUris != null)
                    {
                        foreach (var redirectUri in descriptorDto.RedirectUris)
                        {
                            if (Uri.TryCreate(redirectUri, UriKind.RelativeOrAbsolute, out Uri? luri))
                            {
                                if (luri != null) descriptor.RedirectUris.Add(luri);
                            }
                            else
                            {
                                ModelState.AddModelError("PostLogoutRedirectUri", _sharedLocalizer["Not all Redirect Uri UIs are populated with correct data."]);
                            }
                        }
                    }
                    if (descriptorDto.Requirements != null)
                    {
                        foreach (var requirement in descriptorDto.Requirements)
                        {
                            descriptor.Requirements.Add(requirement);
                        }
                    }
                    if (descriptorDto.DisplayNames != null)
                    {
                        foreach (var dispNm in descriptorDto.DisplayNames)
                        {
                            if(string.IsNullOrEmpty(dispNm.Key) || string.IsNullOrEmpty(dispNm.Value))
                            {
                                ModelState.AddModelError("DisplayNames", _sharedLocalizer["Not all Display Names are populated with correct data."]);
                            } else
                            {
                                try
                                {
                                    CultureInfo ci = new CultureInfo(dispNm.Key);
                                    descriptor.DisplayNames.Add(ci, dispNm.Value);
                                }
                                catch
                                {
                                    ModelState.AddModelError("DisplayNames", _sharedLocalizer["Not all Display Names are populated with correct data."]);
                                }
                            }
                        }
                    }

                    if (ModelState.IsValid)
                    {
                        try
                        {
                            var rslt = await _applicationManager.CreateAsync(descriptor);
                            _logger.LogInformation("Created a new App named:" + descriptor.ClientId + ": " + descriptor.DisplayName);
                            return RedirectToAction(nameof(Index));
                        }
                        catch (Exception ex)
                        {
                            Exception? wex = ex;
                            if (wex != null)
                            {
                                StringBuilder sb = new();
                                while (wex != null)
                                {
                                    sb.Append(wex.Message);
                                    wex = wex.InnerException;
                                }
                                string errorMessage = _sharedLocalizer["Could not create new Application"] + ": " + sb.ToString();
                                ModelState.AddModelError("Create", errorMessage);
                                _logger.LogInformation("Could not create new Application: " + sb.ToString());
                            }
                        }
                    }
                }
            }
            ViewBag.ConsentTypesList = GetConsentTypesList(descriptorDto.ConsentType ?? "");
            ViewBag.ClientTypesList = GetClientTypesList(descriptorDto.ClientType ?? "");
            ViewBag.PermissionsList = GetPermissionsList(descriptorDto.Permissions ?? (Array.Empty<string>()));
            ViewBag.RequirementsList = GetRequirementsList(descriptorDto.Requirements ?? (Array.Empty<string>()));
            ViewBag.CustomPermissions = descriptorDto.CustomPermissions ?? Array.Empty<string>();
            ViewBag.RedirectUris = descriptorDto.RedirectUris ?? (Array.Empty<String>());
            ViewBag.PostLogoutRedirectUris = descriptorDto.PostLogoutRedirectUris ?? (Array.Empty<String>());
            return View(descriptorDto);
        }

        internal async Task<OpenIddictApplicationDescriptorDto?> PrepareDto(string appid)
        {
            var app = await _applicationManager.FindByIdAsync(appid);
            if (app == null)
            {
                return null;
            }
            OpenIddictApplicationDescriptor descriptor = new();
            await _applicationManager.PopulateAsync(descriptor, app);
            OpenIddictApplicationDescriptorDto descriptorDto = new()
            {
                AppId = await _applicationManager.GetIdAsync(app),
                ClientId = descriptor.ClientId,
                ClientSecret = descriptor.ClientSecret,
                DisplayName = descriptor.DisplayName,
                ConsentType = descriptor.ConsentType,
                ClientType = descriptor.Type,

            };
            if (descriptor.RedirectUris.Count > 0)
            {
                List<string> llst = new();
                foreach (var uri in descriptor.RedirectUris)
                {
                    llst.Add(uri.ToString());
                }
                descriptorDto.RedirectUris = llst.ToArray();
            }
            if (descriptor.Requirements.Count > 0)
            {
                descriptorDto.Requirements = descriptor.Requirements.ToArray();
            }
            if (descriptor.PostLogoutRedirectUris.Count > 0)
            {
                List<string> llst = new();
                foreach (var uri in descriptor.PostLogoutRedirectUris)
                {
                    llst.Add(uri.ToString());
                }
                descriptorDto.PostLogoutRedirectUris = llst.ToArray();
            }
            if (descriptor.Permissions.Count > 0)
            {
                List<string> perms = new();
                List<string> custPerms = new();
                foreach (var permission in descriptor.Permissions)
                {
                    if (PermissionItems.Items.Any(i => i == permission))
                    {
                        perms.Add(permission);
                    }
                    else
                    {
                        custPerms.Add(permission);
                    }
                }
                if (perms.Count > 0)
                {
                    descriptorDto.Permissions = perms.ToArray();
                }
                if (custPerms.Count > 0)
                {
                    descriptorDto.CustomPermissions = custPerms.ToArray();
                }
            }
            if(descriptor.DisplayNames.Count > 0)
            {
                descriptorDto.DisplayNames = new List<KeyValuePair<string, string>>();
                foreach(var dn in descriptor.DisplayNames)
                {
                    descriptorDto.DisplayNames.Add(new ( dn.Key.Name, dn.Value ));
                }
            }

            ViewBag.PermissionsList = GetPermissionsList(descriptorDto.Permissions ?? (Array.Empty<string>()));
            ViewBag.CustomPermissions = descriptorDto.CustomPermissions ?? Array.Empty<string>();

            ViewBag.ConsentTypesList = GetConsentTypesList(descriptorDto.ConsentType ?? "");
            ViewBag.ClientTypesList = GetClientTypesList(descriptorDto.ClientType ?? "");

            ViewBag.RequirementsList = GetRequirementsList(descriptorDto.Requirements ?? (Array.Empty<string>()));

            ViewBag.RedirectUris = descriptorDto.RedirectUris ?? (Array.Empty<string>());
            ViewBag.PostLogoutRedirectUris = descriptorDto.PostLogoutRedirectUris ?? (Array.Empty<string>());
            ViewBag.DisplayNames = descriptorDto.DisplayNames ?? (new List<KeyValuePair<string, string>>());

            return descriptorDto;
        }

        // GET: OpenIddictApps/Edit/5
        public async Task<IActionResult> Edit(string appid)
        {
            if (appid == null)
            {
                return NotFound();
            }
            try
            {
                OpenIddictApplicationDescriptorDto? descriptorDto = await PrepareDto(appid);
                if (descriptorDto == null)
                {
                    return NotFound();
                }
                return View(descriptorDto);
            }
            catch (Exception ex)
            {
                Exception? wex = ex;
                StringBuilder sb = new();
                while (wex != null)
                {
                    sb.Append(wex.Message);
                    wex = wex.InnerException;
                }
                return Problem(_sharedLocalizer["Could not find Application by ID."] + "Id=" + appid + sb.ToString());
            }
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Edit(string appid, [Bind("AppId,ClientId,ClientSecret,DisplayName,ConsentType,ClientType,Requirements,RedirectUris,PostLogoutRedirectUris,Permissions,CustomPermissions,DisplayNames")] OpenIddictApplicationDescriptorDto descriptorDto)
        {
            if (appid != descriptorDto.AppId)
            {
                return NotFound();
            }
            if (ModelState.IsValid)
            {
                CheckCollection(descriptorDto);
                if (ModelState.IsValid)
                {

                    try
                    {
                        OpenIddictApplicationDescriptor descriptor = new();
                        var app = await _applicationManager.FindByIdAsync(appid);
                        if (app == null)
                        {
                            return NotFound();
                        }
                        await _applicationManager.PopulateAsync(descriptor, app);
                        descriptor.ClientId = descriptorDto.ClientId;
                        descriptor.ClientSecret = descriptorDto.ClientSecret;
                        descriptor.DisplayName = descriptorDto.DisplayName;
                        descriptor.ConsentType = descriptorDto.ConsentType;
                        descriptor.Type = descriptorDto.ClientType;
                        descriptor.Permissions.Clear();
                        if (descriptorDto.Permissions != null)
                        {
                            foreach (var permission in descriptorDto.Permissions)
                            {
                                descriptor.Permissions.Add(permission);
                            }
                        }
                        if (descriptorDto.CustomPermissions != null)
                        {
                            foreach (var permission in descriptorDto.CustomPermissions)
                            {
                                descriptor.Permissions.Add(permission);
                            }
                        }
                        descriptor.PostLogoutRedirectUris.Clear();
                        if (descriptorDto.PostLogoutRedirectUris != null)
                        {
                            foreach (var postLogoutRedirectUri in descriptorDto.PostLogoutRedirectUris)
                            {
                                if (Uri.TryCreate(postLogoutRedirectUri, UriKind.RelativeOrAbsolute, out Uri? luri))
                                {
                                    if (luri != null) descriptor.PostLogoutRedirectUris.Add(luri);
                                }
                                else
                                {
                                    ModelState.AddModelError("PostLogoutRedirectUri", _sharedLocalizer["Not all Post Logout Redirect Uri UIs are populated with correct data."]);
                                }
                            }
                        }
                        descriptor.RedirectUris.Clear();
                        if (descriptorDto.RedirectUris != null)
                        {
                            foreach (var redirectUri in descriptorDto.RedirectUris)
                            {
                                if (Uri.TryCreate(redirectUri, UriKind.RelativeOrAbsolute, out Uri? luri))
                                {
                                    if (luri != null) descriptor.RedirectUris.Add(luri);
                                }
                                else
                                {
                                    ModelState.AddModelError("PostLogoutRedirectUri", _sharedLocalizer["Not all Redirect Uri UIs are populated with correct data."]);
                                }
                            }
                        }
                        descriptor.Requirements.Clear();
                        if (descriptorDto.Requirements != null)
                        {
                            foreach (var requirement in descriptorDto.Requirements)
                            {
                                descriptor.Requirements.Add(requirement);
                            }
                        }
                        descriptor.DisplayNames.Clear();
                        if (descriptorDto.DisplayNames != null)
                        {
                            foreach (var dispNm in descriptorDto.DisplayNames)
                            {
                                if (string.IsNullOrEmpty(dispNm.Key) || string.IsNullOrEmpty(dispNm.Value))
                                {
                                    ModelState.AddModelError("DisplayNames", _sharedLocalizer["Not all Display Names are populated with correct data."]);
                                }
                                else
                                {
                                    try
                                    {
                                        CultureInfo ci = new(dispNm.Key);
                                        descriptor.DisplayNames.Add(ci, dispNm.Value);
                                    }
                                    catch
                                    {
                                        ModelState.AddModelError("DisplayNames", _sharedLocalizer["Not all Display Names are populated with correct data."]);
                                    }
                                }
                            }
                        }
                        if (ModelState.IsValid)
                        {
                            await _applicationManager.UpdateAsync(app, descriptor);
                            _logger.LogInformation("Updated App with Id:" + appid + ": " + descriptor.ClientId + ": " + descriptor.DisplayName);
                            return RedirectToAction(nameof(Index));
                        }
                    }
                    catch (Exception ex)
                    {
                        Exception? wex = ex;
                        StringBuilder sb = new();
                        while (wex != null)
                        {
                            sb.Append(wex.Message);
                            wex = wex.InnerException;
                        }
                        string errorMessage = _sharedLocalizer["Could not update Application with Id:"] + appid + ": " + sb.ToString();
                        ModelState.AddModelError("Update", errorMessage);
                        _logger.LogInformation("Could not update Application with Id: " + appid + ": " + sb.ToString());
                    }
                }
            }
            ViewBag.ConsentTypesList = GetConsentTypesList(descriptorDto.ConsentType ?? "");
            ViewBag.ClientTypesList = GetClientTypesList(descriptorDto.ClientType ?? "");
            ViewBag.PermissionsList = GetPermissionsList(descriptorDto.Permissions ?? (Array.Empty<string>()));
            ViewBag.RequirementsList = GetRequirementsList(descriptorDto.Requirements ?? (Array.Empty<string>()));
            ViewBag.CustomPermissions = descriptorDto.CustomPermissions ?? Array.Empty<string>();
            ViewBag.RedirectUris = descriptorDto.RedirectUris ?? (Array.Empty<string>());
            ViewBag.PostLogoutRedirectUris = descriptorDto.PostLogoutRedirectUris ?? (Array.Empty<string>());
            ViewBag.DisplayNames = descriptorDto.DisplayNames ?? (new List<KeyValuePair<string, string>>());
            return View(descriptorDto);
        }

        // GET: OpenIddictApps/Details/5
        public async Task<IActionResult> Details(string appid)
        {
            if (appid == null)
            {
                return NotFound();
            }
            try
            {
                OpenIddictApplicationDescriptorDto? descriptorDto = await PrepareDto(appid);
                if (descriptorDto == null)
                {
                    return NotFound();
                }
                return View(descriptorDto);
            }
            catch (Exception ex)
            {
                Exception? wex = ex;
                StringBuilder sb = new();
                while (wex != null)
                {
                    sb.Append(wex.Message);
                    wex = wex.InnerException;
                }
                return Problem(_sharedLocalizer["Could not find Application by ID."] + "Id=" + appid + sb.ToString());
            }
        }

        // GET: OpenIddictApps/Delete/5
        public async Task<IActionResult> Delete(string appid)
        {
            if (appid == null)
            {
                return NotFound();
            }
            try
            {
                OpenIddictApplicationDescriptorDto? descriptorDto = await PrepareDto(appid);
                if (descriptorDto == null)
                {
                    return NotFound();
                }
                return View(descriptorDto);
            }
            catch (Exception ex)
            {
                Exception? wex = ex;
                StringBuilder sb = new();
                while (wex != null)
                {
                    sb.Append(wex.Message);
                    wex = wex.InnerException;
                }
                return Problem(_sharedLocalizer["Could not find Application by ID."] + "Id=" + appid + sb.ToString());
            }
        }

        // POST: OpenIddictApps/Delete/5
        [HttpPost, ActionName("Delete")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteConfirmed(string appid)
        {
            if (appid == null)
            {
                return NotFound();
            }
            try
            {
                var app = await _applicationManager.FindByIdAsync(appid);
                if (app == null)
                {
                    return NotFound();
                }
                await _applicationManager.DeleteAsync(app);
                _logger.LogInformation("Deleted App with Id:" + appid);
            }
            catch (Exception ex)
            {
                Exception? wex = ex;
                StringBuilder sb = new();
                while (wex != null)
                {
                    sb.Append(wex.Message);
                    wex = wex.InnerException;
                }
                return Problem(_sharedLocalizer["Could not delete Application by ID."] + "Id=" + appid + sb.ToString());
            }
            return RedirectToAction(nameof(Index));
        }
    }
}
