using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Localization;
using OpenIdDictMvcContext.Data;
using OpenIdDictMvcLib.Dto;
using OpenIdDictMvcLib.Localizers;
using Microsoft.Extensions.Logging;
using Microsoft.AspNetCore.Authorization;

namespace OpenIdDictMvcLib.Controllers
{
    [Authorize(Roles = $"{OidcIdentityConsts.AdminRoleName}")]
    public class UserRolesController : Controller
    {
        private readonly RoleManager<OidcIdentityRole> _roleManager;
        private readonly UserManager<OidcIdentityUser> _userManager;
        private readonly ILogger<IdentityUserRoleDto> _logger;
        private readonly IStringLocalizer<UserRoleLocalizerResource> _sharedLocalizer;

        public UserRolesController(UserManager<OidcIdentityUser> userManager,
            RoleManager<OidcIdentityRole> roleManager,
            ILogger<IdentityUserRoleDto> logger,
            IStringLocalizer<UserRoleLocalizerResource> SharedLocalizer)
        {
            _userManager = userManager;
            _logger = logger;
            _sharedLocalizer = SharedLocalizer;
            _roleManager = roleManager;
        }

        // GET: UserRoles
        public async Task<IActionResult> Index(string userid)
        {
            List<IdentityUserRoleDto> rslt = new();
            OidcIdentityUser? user = null;
            if (!string.IsNullOrEmpty(userid))
            {
                user = await _userManager.FindByIdAsync(userid);
            }
            if (user != null)
            {
                ViewBag.UserId = user.Id;
                var roles = await _userManager.GetRolesAsync(user);
                foreach (var r in roles)
                {
                    rslt.Add(new IdentityUserRoleDto() { Id = user.Id,  RoleName = r });
                }
            }
            return View(rslt);
        }


        // GET: UserRoles/Create
        public async Task<IActionResult> Create(string userid, string? searchby = null, string? searchstr = null, int? currpg = null)
        {
            if (string.IsNullOrEmpty(userid)) userid = "";
            PageDto pager = new() { PageSize = 10 };
            if (currpg.HasValue)
            {
                pager.CurrentPage = currpg.Value;
            }
            else
            {
                pager.CurrentPage = 1;
            }

            bool SearchById = true;
            if (!string.IsNullOrEmpty(searchby))
            {
                SearchById = searchby == "0";
            }
            ViewBag.SearchBy = new List<SelectListItem>() {
                new SelectListItem(){ Text = _sharedLocalizer["Filter by Role Id"], Value = "0", Selected = SearchById },
                new SelectListItem(){ Text = _sharedLocalizer["Filter by Role Name"], Value = "1", Selected = !SearchById }
            };
            var query = _roleManager.Roles;
            if (!string.IsNullOrEmpty(searchstr))
            {
                ViewBag.SearchString = searchstr;
                if (SearchById)
                    query = query.Where(r => r.Id == searchstr);
                else
                {
                    string qs = searchstr.ToUpper();
                    query = query.Where(r => r.NormalizedName.StartsWith(qs));
                }
            }
            else
            {
                ViewBag.SearchString = "";
            }
            ViewBag.UserId = userid;
            
            int total = await query.CountAsync();
            pager.PageCount = total / pager.PageSize;
            if (pager.PageCount * pager.PageSize < total) pager.PageCount++;
            if ((pager.CurrentPage > pager.PageCount) || (pager.CurrentPage < 1)) pager.CurrentPage = 1;
            pager.PrintFrom = pager.CurrentPage - 2;
            if (pager.PrintFrom < 1) pager.PrintFrom = 1;
            pager.PrintTo = pager.PrintFrom + 5;
            if (pager.PrintTo > pager.PageCount) pager.PrintTo = pager.PageCount;
            ViewBag.SearchById = SearchById ? "0" : "1";
            if (total < 1)
            {
                ViewBag.Pager = pager;
                return View(new List<IdentityUserRoleDto>());
            }
            if (SearchById)
            {
                query = query.OrderBy(r => r.Id);
            }
            else
            {
                query = query.OrderBy(r => r.NormalizedName);
            }
            if (pager.CurrentPage > 1)
            {

                query = query.Skip((pager.CurrentPage - 1) * pager.PageSize);
            }
            ViewBag.Pager = pager;
            return View(await query.AsNoTracking().Take(pager.PageSize).Select(itm => new IdentityUserRoleDto()
            {
                Id = userid,
                RoleName = itm.Name,
            }).ToListAsync());
        }

        // POST: UserRoles/Create
        // To protect from overposting attacks, enable the specific properties you want to bind to.
        // For more details, see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create(string userid, List<string> roles)
        {
            if (string.IsNullOrEmpty(userid)) userid = "";
            if(  (!string.IsNullOrEmpty(userid)) && (roles != null))
            {
                OidcIdentityUser? user = await _userManager.FindByIdAsync(userid);
                if (user != null)
                {
                    foreach (var role in roles)
                    {
                        if (!(await _userManager.IsInRoleAsync(user, role)))
                        {
                            var rslt = await _userManager.AddToRoleAsync(user, role);
                            if (rslt.Succeeded)
                            {
                                _logger.LogInformation("The user with Id:" + user.Id + " was added role with name:" + role);
                            }
                            else
                            {
                                string ExceptionStr = "";
                                if (rslt.Errors != null)
                                {
                                    foreach (var e in rslt.Errors)
                                        ExceptionStr = e.Code + ":" + e.Description;
                                }
                                _logger.LogInformation("Could not add the user with Id:" + user.Id + " to role with name:" + role + " : " + ExceptionStr);
                            }
                        }
                    }
                }
            }
            return RedirectToAction(nameof(Index), new { @userid = userid });
        }



        // POST: UserRoles/Delete/5
        [HttpPost, ActionName("Delete")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteConfirmed(string Id, string RoleName)
        {
            OidcIdentityUser? user = null;
            if ( (!string.IsNullOrEmpty(Id)) && !string.IsNullOrEmpty(RoleName)) 
            {
                user = await _userManager.FindByIdAsync(Id);
            }
            if (user != null)
            {
                if (await _userManager.IsInRoleAsync(user, RoleName))
                {
                    var rslt = await _userManager.RemoveFromRoleAsync(user, RoleName);
                    if (rslt.Succeeded)
                    {
                        _logger.LogInformation("The user with Id:" + user.Id + " was deleted from role with name:" + RoleName);
                        return RedirectToAction(nameof(Index), new { @userid = Id });
                    } else
                    {
                        string ExceptionStr = "";
                        if (rslt.Errors != null)
                        {
                            foreach (var e in rslt.Errors)
                                ExceptionStr = e.Code + ":" + e.Description;
                        }
                        _logger.LogInformation("Could not delete the user with Id:" + user.Id + " from role with name:"+ RoleName + " : " + ExceptionStr);
                    }
                }
            }
            return RedirectToAction(nameof(Index), new { @userid = Id } );
        }

    }
}
