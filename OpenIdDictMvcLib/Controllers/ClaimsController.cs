using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Localization;
using Microsoft.Extensions.Logging;
using OpenIdDictMvcContext.Data;
using OpenIdDictMvcLib.Dto;
using OpenIdDictMvcLib.Localizers;

namespace OpenIdDictMvcLib.Controllers
{
    public class ClaimsController : Controller
    {
        private readonly ApplicationDbContext _context;
        private readonly RoleManager<OidcIdentityRole> _roleManager;
        private readonly UserManager<OidcIdentityUser> _userManager;
        private readonly ILogger<ClaimDescriptorDto> _logger;
        private readonly IConfiguration _configuration;
        private readonly IStringLocalizer<ClaimLocalizerResource> _sharedLocalizer;
        private readonly string _claimprefixval = "";

        public ClaimsController(ApplicationDbContext context,
            UserManager<OidcIdentityUser> userManager,
            RoleManager<OidcIdentityRole> roleManager,
            ILogger<ClaimDescriptorDto> logger,
            IConfiguration configuration,
            IStringLocalizer<ClaimLocalizerResource> SharedLocalizer)
        {
            _context = context;
            _roleManager = roleManager;
            _userManager = userManager;
            _logger = logger;
            _configuration = configuration;
            _sharedLocalizer = SharedLocalizer;
            _claimprefixval = _configuration[nameof(OidcAllowedScope) + ":" + nameof(OidcAllowedScope.ClaimPrefix)];
            if (string.IsNullOrEmpty(_claimprefixval)) _claimprefixval = OidcAllowedScope.ClaimPrefix + "."; else _claimprefixval += ".";

        }

        // GET: Claims
        public async Task<IActionResult> Index(string idtype, string prntid)
        {
            IList<Claim>? claims = null;
            if (idtype=="user")
            {
                var identityUserDto = await _userManager.FindByIdAsync(prntid);
                if(identityUserDto ==null) { return NotFound(); }
                claims = await _userManager.GetClaimsAsync(identityUserDto);
            } else if (idtype == "role")
            {
                var identityRoleDto = await _roleManager.FindByIdAsync(prntid);
                if (identityRoleDto == null) { return NotFound(); }
                claims = await _roleManager.GetClaimsAsync(identityRoleDto);
            } 
            if(claims == null) { return NotFound(); }
            ViewBag.IdType = idtype;
            ViewBag.PrntId = prntid;
            IList<ClaimDto> rslt = claims.Select(c => new ClaimDto
            {
                ClaimType = c.Type,
                ClaimValue = c.Value,
                Issuer = c.Issuer,
                OriginalIssuer = c.OriginalIssuer,
                ClaimValueType = c.ValueType,
            }).ToList();
            return View(rslt);
        }
        
        internal static List<SelectListItem> GetClaimValueTypesList(string sel)
        {
            return new List<SelectListItem>() {
                new SelectListItem { Value = ClaimValueTypes.Base64Binary, Text = nameof(ClaimValueTypes.Base64Binary), Selected = ClaimValueTypes.Base64Binary == sel  },
                new SelectListItem { Value = ClaimValueTypes.UpnName, Text = nameof(ClaimValueTypes.UpnName), Selected = ClaimValueTypes.UpnName == sel  },
                new SelectListItem { Value = ClaimValueTypes.UInteger64, Text = nameof(ClaimValueTypes.UInteger64), Selected = ClaimValueTypes.UInteger64 == sel  },
                new SelectListItem { Value = ClaimValueTypes.UInteger32, Text = nameof(ClaimValueTypes.UInteger32), Selected = ClaimValueTypes.UInteger32 == sel  },
                new SelectListItem { Value = ClaimValueTypes.Time, Text = nameof(ClaimValueTypes.Time), Selected = ClaimValueTypes.Time == sel  },
                new SelectListItem { Value = ClaimValueTypes.String, Text = nameof(ClaimValueTypes.String), Selected = ClaimValueTypes.String == sel  },
                new SelectListItem { Value = ClaimValueTypes.Sid, Text = nameof(ClaimValueTypes.Sid), Selected = ClaimValueTypes.Sid == sel  },
                new SelectListItem { Value = ClaimValueTypes.RsaKeyValue, Text = nameof(ClaimValueTypes.RsaKeyValue), Selected = ClaimValueTypes.RsaKeyValue == sel  },
                new SelectListItem { Value = ClaimValueTypes.Rsa, Text = nameof(ClaimValueTypes.Rsa), Selected = ClaimValueTypes.Rsa == sel  },
                new SelectListItem { Value = ClaimValueTypes.Rfc822Name, Text = nameof(ClaimValueTypes.Rfc822Name), Selected = ClaimValueTypes.Rfc822Name == sel  },
                new SelectListItem { Value = ClaimValueTypes.KeyInfo, Text = nameof(ClaimValueTypes.KeyInfo), Selected = ClaimValueTypes.KeyInfo == sel  },
                new SelectListItem { Value = ClaimValueTypes.Integer64, Text = nameof(ClaimValueTypes.Integer64), Selected = ClaimValueTypes.Integer64 == sel  },
                new SelectListItem { Value = ClaimValueTypes.X500Name, Text = nameof(ClaimValueTypes.X500Name), Selected = ClaimValueTypes.X500Name == sel  },
                new SelectListItem { Value = ClaimValueTypes.Integer32, Text = nameof(ClaimValueTypes.Integer32), Selected = ClaimValueTypes.Integer32 == sel  },
                new SelectListItem { Value = ClaimValueTypes.HexBinary, Text = nameof(ClaimValueTypes.HexBinary), Selected = ClaimValueTypes.HexBinary == sel  },
                new SelectListItem { Value = ClaimValueTypes.Fqbn, Text = nameof(ClaimValueTypes.Fqbn), Selected = ClaimValueTypes.Fqbn == sel  },
                new SelectListItem { Value = ClaimValueTypes.Email, Text = nameof(ClaimValueTypes.Email), Selected = ClaimValueTypes.Email == sel  },
                new SelectListItem { Value = ClaimValueTypes.DsaKeyValue, Text = nameof(ClaimValueTypes.DsaKeyValue), Selected = ClaimValueTypes.DsaKeyValue == sel  },
                new SelectListItem { Value = ClaimValueTypes.Double, Text = nameof(ClaimValueTypes.Double), Selected = ClaimValueTypes.Double == sel  },
                new SelectListItem { Value = ClaimValueTypes.DnsName, Text = nameof(ClaimValueTypes.DnsName), Selected = ClaimValueTypes.DnsName == sel  },
                new SelectListItem { Value = ClaimValueTypes.DaytimeDuration, Text = nameof(ClaimValueTypes.DaytimeDuration), Selected = ClaimValueTypes.DaytimeDuration == sel  },
                new SelectListItem { Value = ClaimValueTypes.DateTime, Text = nameof(ClaimValueTypes.DateTime), Selected = ClaimValueTypes.DateTime == sel  },
                new SelectListItem { Value = ClaimValueTypes.Date, Text = nameof(ClaimValueTypes.Date), Selected = ClaimValueTypes.Date == sel  },
                new SelectListItem { Value = ClaimValueTypes.Boolean, Text = nameof(ClaimValueTypes.Boolean), Selected = ClaimValueTypes.Boolean == sel  },
                new SelectListItem { Value = ClaimValueTypes.Base64Octet, Text = nameof(ClaimValueTypes.Base64Octet), Selected = ClaimValueTypes.Base64Octet == sel  },
                new SelectListItem { Value = ClaimValueTypes.Integer, Text = nameof(ClaimValueTypes.Integer), Selected = ClaimValueTypes.Integer == sel  },
                new SelectListItem { Value = ClaimValueTypes.YearMonthDuration, Text = nameof(ClaimValueTypes.YearMonthDuration), Selected = ClaimValueTypes.YearMonthDuration == sel  },
            };
        }

        internal List<SelectListItem> GetClaimTypesList(string sel)
        {
            return new List<SelectListItem>() {
                new SelectListItem { Value = ClaimTypes.Actor, Text = nameof(ClaimTypes.Actor), Selected = ClaimTypes.Actor == sel  },
                new SelectListItem { Value = ClaimTypes.PostalCode, Text = nameof(ClaimTypes.PostalCode), Selected = ClaimTypes.PostalCode == sel  },
                new SelectListItem { Value = ClaimTypes.PrimaryGroupSid, Text = nameof(ClaimTypes.PrimaryGroupSid), Selected = ClaimTypes.PrimaryGroupSid == sel  },
                new SelectListItem { Value = ClaimTypes.PrimarySid, Text = nameof(ClaimTypes.PrimarySid), Selected = ClaimTypes.PrimarySid == sel  },
                new SelectListItem { Value = ClaimTypes.Role, Text = nameof(ClaimTypes.Role), Selected = ClaimTypes.Role == sel  },
                new SelectListItem { Value = ClaimTypes.Rsa, Text = nameof(ClaimTypes.Rsa), Selected = ClaimTypes.Rsa == sel  },
                new SelectListItem { Value = ClaimTypes.SerialNumber, Text = nameof(ClaimTypes.SerialNumber), Selected = ClaimTypes.SerialNumber == sel  },
                new SelectListItem { Value = ClaimTypes.Sid, Text = nameof(ClaimTypes.Sid), Selected = ClaimTypes.Sid == sel  },
                new SelectListItem { Value = ClaimTypes.Spn, Text = nameof(ClaimTypes.Spn), Selected = ClaimTypes.Spn == sel  },
                new SelectListItem { Value = ClaimTypes.StateOrProvince, Text = nameof(ClaimTypes.StateOrProvince), Selected = ClaimTypes.StateOrProvince == sel  },
                new SelectListItem { Value = ClaimTypes.StreetAddress, Text = nameof(ClaimTypes.StreetAddress), Selected = ClaimTypes.StreetAddress == sel  },
                new SelectListItem { Value = ClaimTypes.Surname, Text = nameof(ClaimTypes.Surname), Selected = ClaimTypes.Surname == sel  },
                new SelectListItem { Value = ClaimTypes.System, Text = nameof(ClaimTypes.System), Selected = ClaimTypes.System == sel  },
                new SelectListItem { Value = ClaimTypes.Thumbprint, Text = nameof(ClaimTypes.Thumbprint), Selected = ClaimTypes.Thumbprint == sel  },
                new SelectListItem { Value = ClaimTypes.Upn, Text = nameof(ClaimTypes.Upn), Selected = ClaimTypes.Upn == sel  },
                new SelectListItem { Value = ClaimTypes.Uri, Text = nameof(ClaimTypes.Uri), Selected = ClaimTypes.Uri == sel  },
                new SelectListItem { Value = ClaimTypes.UserData, Text = nameof(ClaimTypes.UserData), Selected = ClaimTypes.UserData == sel  },
                new SelectListItem { Value = ClaimTypes.Version, Text = nameof(ClaimTypes.Version), Selected = ClaimTypes.Version == sel  },
                new SelectListItem { Value = ClaimTypes.Webpage, Text = nameof(ClaimTypes.Webpage), Selected = ClaimTypes.Webpage == sel  },
                new SelectListItem { Value = ClaimTypes.WindowsAccountName, Text = nameof(ClaimTypes.WindowsAccountName), Selected = ClaimTypes.WindowsAccountName == sel  },
                new SelectListItem { Value = ClaimTypes.WindowsDeviceClaim, Text = nameof(ClaimTypes.WindowsDeviceClaim), Selected = ClaimTypes.WindowsDeviceClaim == sel  },
                new SelectListItem { Value = ClaimTypes.WindowsDeviceGroup, Text = nameof(ClaimTypes.WindowsDeviceGroup), Selected = ClaimTypes.WindowsDeviceGroup == sel  },
                new SelectListItem { Value = ClaimTypes.WindowsFqbnVersion, Text = nameof(ClaimTypes.WindowsFqbnVersion), Selected = ClaimTypes.WindowsFqbnVersion == sel  },
                new SelectListItem { Value = ClaimTypes.WindowsSubAuthority, Text = nameof(ClaimTypes.WindowsSubAuthority), Selected = ClaimTypes.WindowsSubAuthority == sel  },
                new SelectListItem { Value = ClaimTypes.OtherPhone, Text = nameof(ClaimTypes.OtherPhone), Selected = ClaimTypes.OtherPhone == sel  },
                new SelectListItem { Value = ClaimTypes.NameIdentifier, Text = nameof(ClaimTypes.NameIdentifier), Selected = ClaimTypes.NameIdentifier == sel  },
                new SelectListItem { Value = ClaimTypes.Name, Text = nameof(ClaimTypes.Name), Selected = ClaimTypes.Name == sel  },
                new SelectListItem { Value = ClaimTypes.MobilePhone, Text = nameof(ClaimTypes.MobilePhone), Selected = ClaimTypes.MobilePhone == sel  },
                new SelectListItem { Value = ClaimTypes.Anonymous, Text = nameof(ClaimTypes.Anonymous), Selected = ClaimTypes.Anonymous == sel  },
                new SelectListItem { Value = ClaimTypes.Authentication, Text = nameof(ClaimTypes.Authentication), Selected = ClaimTypes.Authentication == sel  },
                new SelectListItem { Value = ClaimTypes.AuthenticationInstant, Text = nameof(ClaimTypes.AuthenticationInstant), Selected = ClaimTypes.AuthenticationInstant == sel  },
                new SelectListItem { Value = ClaimTypes.AuthenticationMethod, Text = nameof(ClaimTypes.AuthenticationMethod), Selected = ClaimTypes.AuthenticationMethod == sel  },
                new SelectListItem { Value = ClaimTypes.AuthorizationDecision, Text = nameof(ClaimTypes.AuthorizationDecision), Selected = ClaimTypes.AuthorizationDecision == sel  },
                new SelectListItem { Value = ClaimTypes.CookiePath, Text = nameof(ClaimTypes.CookiePath), Selected = ClaimTypes.CookiePath == sel  },
                new SelectListItem { Value = ClaimTypes.Country, Text = nameof(ClaimTypes.Country), Selected = ClaimTypes.Country == sel  },
                new SelectListItem { Value = ClaimTypes.DateOfBirth, Text = nameof(ClaimTypes.DateOfBirth), Selected = ClaimTypes.DateOfBirth == sel  },
                new SelectListItem { Value = ClaimTypes.DenyOnlyPrimaryGroupSid, Text = nameof(ClaimTypes.DenyOnlyPrimaryGroupSid), Selected = ClaimTypes.DenyOnlyPrimaryGroupSid == sel  },
                new SelectListItem { Value = ClaimTypes.DenyOnlyPrimarySid, Text = nameof(ClaimTypes.DenyOnlyPrimarySid), Selected = ClaimTypes.DenyOnlyPrimarySid == sel  },
                new SelectListItem { Value = ClaimTypes.DenyOnlySid, Text = nameof(ClaimTypes.DenyOnlySid), Selected = ClaimTypes.DenyOnlySid == sel  },
                new SelectListItem { Value = ClaimTypes.WindowsUserClaim, Text = nameof(ClaimTypes.WindowsUserClaim), Selected = ClaimTypes.WindowsUserClaim == sel  },
                new SelectListItem { Value = ClaimTypes.DenyOnlyWindowsDeviceGroup, Text = nameof(ClaimTypes.DenyOnlyWindowsDeviceGroup), Selected = ClaimTypes.DenyOnlyWindowsDeviceGroup == sel  },
                new SelectListItem { Value = ClaimTypes.Dsa, Text = nameof(ClaimTypes.Dsa), Selected = ClaimTypes.Dsa == sel  },
                new SelectListItem { Value = ClaimTypes.Email, Text = nameof(ClaimTypes.Email), Selected = ClaimTypes.Email == sel  },
                new SelectListItem { Value = ClaimTypes.Expiration, Text = nameof(ClaimTypes.Expiration), Selected = ClaimTypes.Expiration == sel  },
                new SelectListItem { Value = ClaimTypes.Expired, Text = nameof(ClaimTypes.Expired), Selected = ClaimTypes.Expired == sel  },
                new SelectListItem { Value = ClaimTypes.Gender, Text = nameof(ClaimTypes.Gender), Selected = ClaimTypes.Gender == sel  },
                new SelectListItem { Value = ClaimTypes.GivenName, Text = nameof(ClaimTypes.GivenName), Selected = ClaimTypes.GivenName == sel  },
                new SelectListItem { Value = ClaimTypes.GroupSid, Text = nameof(ClaimTypes.GroupSid), Selected = ClaimTypes.GroupSid == sel  },
                new SelectListItem { Value = ClaimTypes.Hash, Text = nameof(ClaimTypes.Hash), Selected = ClaimTypes.Hash == sel  },
                new SelectListItem { Value = ClaimTypes.HomePhone, Text = nameof(ClaimTypes.HomePhone), Selected = ClaimTypes.HomePhone == sel  },
                new SelectListItem { Value = ClaimTypes.IsPersistent, Text = nameof(ClaimTypes.IsPersistent), Selected = ClaimTypes.IsPersistent == sel  },
                new SelectListItem { Value = ClaimTypes.Locality, Text = nameof(ClaimTypes.Locality), Selected = ClaimTypes.Locality == sel  },
                new SelectListItem { Value = ClaimTypes.Dns, Text = nameof(ClaimTypes.Dns), Selected = ClaimTypes.Dns == sel  },
                new SelectListItem { Value = ClaimTypes.X500DistinguishedName, Text = nameof(ClaimTypes.X500DistinguishedName), Selected = ClaimTypes.X500DistinguishedName == sel  },
                new SelectListItem { Value = _claimprefixval, Text = nameof(OidcAllowedScope) + ":" + nameof(OidcAllowedScope.ClaimPrefix), Selected = _claimprefixval == sel  },
            };
        }

        // GET: Claims/Create
        public IActionResult Create(string idtype, string prntid)
        {

            if (!string.IsNullOrEmpty(idtype))
                ViewBag.IdType = idtype;
            if (!string.IsNullOrEmpty(prntid))
                ViewBag.PrntId = prntid;
            ViewBag.ClaimValueTypesList = GetClaimValueTypesList(ClaimValueTypes.String);
            ViewBag.ClaimTypesList = GetClaimTypesList(_claimprefixval);
            ClaimDescriptorDto сlaimDescriptorDto = new()
            {
                ClaimValueType = ClaimValueTypes.String,
                Issuer = ClaimsIdentity.DefaultIssuer,
                OriginalIssuer = ClaimsIdentity.DefaultIssuer,
                ClaimType = _claimprefixval
            };
            return View(сlaimDescriptorDto);
        }
        // POST: Claims/Create
        // To protect from overposting attacks, enable the specific properties you want to bind to.
        // For more details, see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create(string idtype, string prntid, [Bind("ClaimType,Issuer,OriginalIssuer,ClaimValue,ClaimValueType,ClaimProperties")] ClaimDescriptorDto сlaimDescriptorDto)
        {
            if (ModelState.IsValid)
            {
                if(сlaimDescriptorDto.ClaimProperties != null)
                {
                    for(int i = 0; i < сlaimDescriptorDto.ClaimProperties.Count;i++)
                    {
                        if(string.IsNullOrEmpty(сlaimDescriptorDto.ClaimProperties[i].Key))
                        {
                            ModelState.AddModelError("AddClaim", _sharedLocalizer["Claim property keys cannot be null or empty."]);
                            break;
                        } 
                    }
                    if (ModelState.IsValid)
                    {
                        for (int i = 0; i < сlaimDescriptorDto.ClaimProperties.Count-1; i++)
                        {
                            for(int j = i+1; j < сlaimDescriptorDto.ClaimProperties.Count ; j++)
                            {
                                if (сlaimDescriptorDto.ClaimProperties[i].Key == сlaimDescriptorDto.ClaimProperties[j].Key)
                                {
                                    ModelState.AddModelError("AddClaim", _sharedLocalizer["Two Claim properties have identical key."]);
                                    break;
                                }
                            }
                        }
                    }
                }
                if (ModelState.IsValid)
                {
                    if (idtype == "user")
                    {
                        var identityUserDto = await _userManager.FindByIdAsync(prntid);
                        if (identityUserDto == null)
                        {
                            ModelState.AddModelError("RoleId", _sharedLocalizer["Failed to find user by id:"] + prntid);
                        }
                        else
                        {
                            Claim uclm = new(сlaimDescriptorDto.ClaimType ?? "", сlaimDescriptorDto.ClaimValue ?? "", 
                                сlaimDescriptorDto.ClaimValueType, сlaimDescriptorDto.Issuer, сlaimDescriptorDto.OriginalIssuer);
                            if (сlaimDescriptorDto.ClaimProperties != null)
                            {
                                foreach (var kv in сlaimDescriptorDto.ClaimProperties)
                                {
                                    uclm.Properties.Add(kv);
                                }
                            }
                            var urslt = await _userManager.AddClaimAsync(identityUserDto, uclm);
                            if (urslt.Succeeded)
                            {
                                _logger.LogInformation("Created a new Claim with type:" + uclm.Type + "For User with Id:" + prntid);
                                return RedirectToAction(nameof(Index), new { idtype = idtype, prntid = prntid });
                            }
                            else
                            {
                                StringBuilder umsgs = new();
                                umsgs.AppendLine(_sharedLocalizer["Failed to add claim to user:"]);
                                if (urslt.Errors != null)
                                {
                                    foreach (var error in urslt.Errors)
                                    {
                                        umsgs.AppendLine(error.Code + ":" + error.Description);
                                    }
                                }
                                ModelState.AddModelError("AddClaim", umsgs.ToString());
                            }
                        }
                    }
                    else if (idtype == "role")
                    {
                        var identityRoleDto = await _roleManager.FindByIdAsync(prntid);
                        if (identityRoleDto == null)
                        {
                            ModelState.AddModelError("RoleId", _sharedLocalizer["Failed to find role by id:"] + prntid);
                        }
                        else
                        {
                            Claim rclm = new(сlaimDescriptorDto.ClaimType ?? "", сlaimDescriptorDto.ClaimValue ?? "",
                                сlaimDescriptorDto.ClaimValueType, сlaimDescriptorDto.Issuer, сlaimDescriptorDto.OriginalIssuer);
                            if (сlaimDescriptorDto.ClaimProperties != null)
                            {
                                foreach(var kv in сlaimDescriptorDto.ClaimProperties)
                                {
                                    rclm.Properties.Add(kv);
                                }
                            }

                            var rrslt = await _roleManager.AddClaimAsync(identityRoleDto, rclm);
                            if (rrslt.Succeeded)
                            {
                                _logger.LogInformation("Created a new Claim with type:" + rclm.Type + "For Role with Id:" + prntid);
                                return RedirectToAction(nameof(Index), new { idtype = idtype, prntid = prntid });
                            }
                            else
                            {
                                StringBuilder rmsgs = new();
                                rmsgs.AppendLine(_sharedLocalizer["Failed to add claim to role:"]);
                                if (rrslt.Errors != null)
                                {
                                    foreach (var error in rrslt.Errors)
                                    {
                                        rmsgs.AppendLine(error.Code + ":" + error.Description);
                                    }
                                }
                                ModelState.AddModelError("AddClaim", rmsgs.ToString());
                            }
                        }
                    }
                }
            }

            if (!string.IsNullOrEmpty(idtype))
                ViewBag.IdType = idtype;
            if (!string.IsNullOrEmpty(prntid))
                ViewBag.PrntId = prntid;
            ViewBag.ClaimValueTypesList = GetClaimValueTypesList(сlaimDescriptorDto.ClaimValueType?? ClaimValueTypes.String);
            ViewBag.ClaimTypesList = GetClaimTypesList(сlaimDescriptorDto.ClaimType ?? ClaimTypes.Actor);

            return View(сlaimDescriptorDto);
        }

        internal ClaimDescriptorDto PrepareDto(ClaimDescriptorDto? сlaimDescriptorDto, Claim clm)
        {
            ClaimDescriptorDto rslt = сlaimDescriptorDto ?? new ClaimDescriptorDto();
            rslt.ClaimType = clm.Type;
            rslt.ClaimValue = clm.Value;
            rslt.ClaimValueType = clm.ValueType;
            rslt.Issuer = clm.Issuer;
            rslt.OriginalIssuer = clm.OriginalIssuer;
            if (clm.Properties.Count > 0)
            {
                rslt.ClaimProperties = new List<KeyValuePair<string, string>>();
                foreach (var i in clm.Properties)
                {
                    rslt.ClaimProperties.Add(i);
                }
            }
            return rslt;
        }

        // GET: Claims/Details/5
        public async Task<IActionResult> Details(string idtype, string prntid, string claimtype,  string claimvalue)
        {
            if( string.IsNullOrEmpty(idtype) || string.IsNullOrEmpty(prntid) || string.IsNullOrEmpty(claimtype))
            {
                return NotFound();  
            }


            ClaimDescriptorDto? сlaimDescriptorDto = null;
            if (idtype == "user")
            {
                var identityUserDto = await _userManager.FindByIdAsync(prntid);
                if (identityUserDto == null) { return NotFound(); }
                Claim? uclm = null;
                if(string.IsNullOrEmpty(claimvalue))
                    uclm = (await _userManager.GetClaimsAsync(identityUserDto)).Where(c=>c.Type == claimtype && string.IsNullOrEmpty(c.Value)).FirstOrDefault();
                else
                    uclm = (await _userManager.GetClaimsAsync(identityUserDto)).Where(c => c.Type == claimtype && c.Value == claimvalue).FirstOrDefault();
                if(uclm == null) { return NotFound(); }
                сlaimDescriptorDto = PrepareDto(null, uclm);
            }
            else if (idtype == "role")
            {
                var identityRoleDto = await _roleManager.FindByIdAsync(prntid);
                if (identityRoleDto == null) { return NotFound(); }
                Claim? rclm = null;
                if (string.IsNullOrEmpty(claimvalue))
                    rclm = (await _roleManager.GetClaimsAsync(identityRoleDto)).Where(c => c.Type == claimtype && string.IsNullOrEmpty(c.Value)).FirstOrDefault();
                else
                    rclm = (await _roleManager.GetClaimsAsync(identityRoleDto)).Where(c => c.Type == claimtype && c.Value == claimvalue).FirstOrDefault();
                if (rclm == null) { return NotFound(); }
                сlaimDescriptorDto = PrepareDto(null, rclm);
            }
            if (!string.IsNullOrEmpty(idtype))
                ViewBag.IdType = idtype;
            if (!string.IsNullOrEmpty(prntid))
                ViewBag.PrntId = prntid;
            if (сlaimDescriptorDto != null)
            {
                ViewBag.ClaimValueTypesList = GetClaimValueTypesList(сlaimDescriptorDto.ClaimValueType ?? "");
                ViewBag.ClaimTypesList = GetClaimTypesList(сlaimDescriptorDto.ClaimType ?? "");
            } else
            {
                ViewBag.ClaimValueTypesList = GetClaimValueTypesList("");
                ViewBag.ClaimTypesList = GetClaimTypesList("");
            }
            return View(сlaimDescriptorDto);
        }


        // GET: Claims/Delete/5
        public async Task<IActionResult> Delete(string idtype, string prntid, string claimtype, string claimvalue)
        {
            if (string.IsNullOrEmpty(idtype) || string.IsNullOrEmpty(prntid) || string.IsNullOrEmpty(claimtype))
            {
                return NotFound();
            }


            ClaimDescriptorDto? сlaimDescriptorDto = null;
            if (idtype == "user")
            {
                var identityUserDto = await _userManager.FindByIdAsync(prntid);
                if (identityUserDto == null) { return NotFound(); }
                Claim? uclm = null;
                if (string.IsNullOrEmpty(claimvalue))
                    uclm = (await _userManager.GetClaimsAsync(identityUserDto)).Where(c => c.Type == claimtype && string.IsNullOrEmpty(c.Value)).FirstOrDefault();
                else
                    uclm = (await _userManager.GetClaimsAsync(identityUserDto)).Where(c => c.Type == claimtype && c.Value == claimvalue).FirstOrDefault();
                if (uclm == null) { return NotFound(); }
                сlaimDescriptorDto = PrepareDto(null, uclm);
            }
            else if (idtype == "role")
            {
                var identityRoleDto = await _roleManager.FindByIdAsync(prntid);
                if (identityRoleDto == null) { return NotFound(); }
                Claim? rclm = null;
                if (string.IsNullOrEmpty(claimvalue))
                    rclm = (await _roleManager.GetClaimsAsync(identityRoleDto)).Where(c => c.Type == claimtype && string.IsNullOrEmpty(c.Value)).FirstOrDefault();
                else
                    rclm = (await _roleManager.GetClaimsAsync(identityRoleDto)).Where(c => c.Type == claimtype && c.Value == claimvalue).FirstOrDefault();
                if (rclm == null) { return NotFound(); }
                сlaimDescriptorDto = PrepareDto(null, rclm);
            }
            if (!string.IsNullOrEmpty(idtype))
                ViewBag.IdType = idtype;
            if (!string.IsNullOrEmpty(prntid))
                ViewBag.PrntId = prntid;
            if (сlaimDescriptorDto != null)
            {
                ViewBag.ClaimValueTypesList = GetClaimValueTypesList(сlaimDescriptorDto.ClaimValueType ?? "");
                ViewBag.ClaimTypesList = GetClaimTypesList(сlaimDescriptorDto.ClaimType ?? "");
            }
            else
            {
                ViewBag.ClaimValueTypesList = GetClaimValueTypesList("");
                ViewBag.ClaimTypesList = GetClaimTypesList("");
            }
            return View(сlaimDescriptorDto);
        }

        // POST: Claims/Delete/5
        [HttpPost, ActionName("Delete")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteConfirmed(string idtype, string prntid, string claimtype, string claimvalue)
        {
            if (string.IsNullOrEmpty(idtype) || string.IsNullOrEmpty(prntid) || string.IsNullOrEmpty(claimtype))
            {
                return NotFound();
            }


            ClaimDescriptorDto? сlaimDescriptorDto = null;
            if (idtype == "user")
            {
                var identityUserDto = await _userManager.FindByIdAsync(prntid);
                if (identityUserDto == null) { return NotFound(); }
                Claim? uclm = null;
                if (string.IsNullOrEmpty(claimvalue))
                    uclm = (await _userManager.GetClaimsAsync(identityUserDto)).Where(c => c.Type == claimtype && string.IsNullOrEmpty(c.Value)).FirstOrDefault();
                else
                    uclm = (await _userManager.GetClaimsAsync(identityUserDto)).Where(c => c.Type == claimtype && c.Value == claimvalue).FirstOrDefault();
                if (uclm == null) { return NotFound(); }
                var rrslt = await _userManager.RemoveClaimAsync(identityUserDto, uclm);
                if (rrslt.Succeeded)
                {
                    _logger.LogInformation("Deleted a Claim with type:" + uclm.Type + "For User with Id:" + prntid);
                    return RedirectToAction(nameof(Index), new { idtype = idtype, prntid = prntid });
                }
                StringBuilder rmsgs = new();
                rmsgs.AppendLine(_sharedLocalizer["Failed to delete claim:"]);
                if (rrslt.Errors != null)
                {
                    foreach (var error in rrslt.Errors)
                    {
                        rmsgs.AppendLine(error.Code + ":" + error.Description);
                    }
                }
                ModelState.AddModelError("DeleteClaim", rmsgs.ToString());
                сlaimDescriptorDto = PrepareDto(null, uclm);
            }
            else if (idtype == "role")
            {
                var identityRoleDto = await _roleManager.FindByIdAsync(prntid);
                if (identityRoleDto == null) { return NotFound(); }
                Claim? rclm = null;
                if (string.IsNullOrEmpty(claimvalue))
                    rclm = (await _roleManager.GetClaimsAsync(identityRoleDto)).Where(c => c.Type == claimtype && string.IsNullOrEmpty(c.Value)).FirstOrDefault();
                else
                    rclm = (await _roleManager.GetClaimsAsync(identityRoleDto)).Where(c => c.Type == claimtype && c.Value == claimvalue).FirstOrDefault();
                if (rclm == null) { return NotFound(); }
                var rrslt = await _roleManager.RemoveClaimAsync(identityRoleDto, rclm);
                if(rrslt.Succeeded)
                {
                    _logger.LogInformation("Deleted a Claim with type:" + rclm.Type + "For Role with Id:" + prntid);
                    return RedirectToAction(nameof(Index), new { idtype = idtype, prntid = prntid });
                } 
                StringBuilder rmsgs = new();
                rmsgs.AppendLine(_sharedLocalizer["Failed to delete claim:"]);
                if (rrslt.Errors != null)
                {
                    foreach (var error in rrslt.Errors)
                    {
                        rmsgs.AppendLine(error.Code + ":" + error.Description);
                    }
                }
                ModelState.AddModelError("DeleteClaim", rmsgs.ToString());
                сlaimDescriptorDto = PrepareDto(null, rclm);
            }

            if (!string.IsNullOrEmpty(idtype))
                ViewBag.IdType = idtype;
            if (!string.IsNullOrEmpty(prntid))
                ViewBag.PrntId = prntid;
            if (сlaimDescriptorDto != null)
            {
                ViewBag.ClaimValueTypesList = GetClaimValueTypesList(сlaimDescriptorDto.ClaimValueType ?? "");
                ViewBag.ClaimTypesList = GetClaimTypesList(сlaimDescriptorDto.ClaimType ?? "");
            }
            else
            {
                ViewBag.ClaimValueTypesList = GetClaimValueTypesList("");
                ViewBag.ClaimTypesList = GetClaimTypesList("");
            }

            return View(сlaimDescriptorDto);


        }


    }
}
