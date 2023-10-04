using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Localization;
using Microsoft.Extensions.Logging;
using OpenIdDictMvcContext.Data;
using OpenIdDictMvcLib.Dto;
using OpenIdDictMvcLib.Localizers;
using System.Text;

namespace OpenIdDictMvcLib.Controllers
{
    [Authorize(Roles = $"{OidcIdentityConsts.AdminRoleName}")]
    public class OidcUserGroupsController : Controller
    {
        private readonly UserManager<OidcIdentityUser> _userManager;
        private readonly IStringLocalizer<OidcUserGroupLocalizerResource> _sharedLocalizer;
        private readonly ILogger<OidcUserGroupDto> _logger;
        private readonly ApplicationDbContext _context;

        public OidcUserGroupsController(
            ApplicationDbContext context,
            UserManager<OidcIdentityUser> userManager,
            ILogger<OidcUserGroupDto> logger,
            IStringLocalizer<OidcUserGroupLocalizerResource> SharedLocalizer)
        {
            _userManager = userManager;
            _logger = logger;
            _sharedLocalizer = SharedLocalizer;
            _context = context;
        }

        public async Task<IActionResult> Index(string userid)
        {
            List<OidcUserGroupDto> rslt = new();
            OidcIdentityUser? user = null;
            if (!string.IsNullOrEmpty(userid))
            {
                user = await _userManager.FindByIdAsync(userid);
            }
            if (user != null)
            {
                ViewBag.UserId = user.Id;
                rslt = await _context.OidcUserGroups.Where(g => g.OidcUserId == userid)
                    .Select(g=> new OidcUserGroupDto
                    {
                        OidcUserId = g.OidcUserId,
                        OidcGroupId = g.OidcGroupId,
                        OidcGroupName = g.Group.OidcGroupName,
                        OidcGroupDisplayName = g.Group.OidcGroupDisplayName
                    }).ToListAsync();
            }
            return View(rslt);
        }

        // POST: OidcUserGroups/Delete/5
        [HttpPost, ActionName("Delete")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteConfirmed(string oidcuserid, string oidcgroupid)
        {
            if ((!string.IsNullOrEmpty(oidcuserid)) && !string.IsNullOrEmpty(oidcgroupid))
            {
                var ug = await _context.OidcUserGroups.Where(g => g.OidcUserId == oidcuserid && g.OidcGroupId == oidcgroupid).FirstOrDefaultAsync();
                if(ug != null)
                {
                    _context.Remove(ug);
                    try
                    {
                        await _context.SaveChangesAsync();
                        _logger.LogInformation("Deleted a User Group with user ID:" + ug.OidcUserId + " " + "and group ID:" + ug.OidcGroupId);
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
                        _logger.LogInformation("Could not Delete a User Group with user ID:" + ug.OidcUserId + " " + "and group ID:" + ug.OidcGroupId + ": " + sb.ToString());
                    }

                }
            }
            return RedirectToAction(nameof(Index), new { @userid = oidcuserid });
        }

        // GET: OidcUserGroups/Create
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
                new SelectListItem(){ Text = _sharedLocalizer["Filter by Group Id"], Value = "0", Selected = SearchById },
                new SelectListItem(){ Text = _sharedLocalizer["Filter by Group Name"], Value = "1", Selected = !SearchById }
            };
            var query = _context.OidcGroups.AsQueryable();
            if (!string.IsNullOrEmpty(searchstr))
            {
                ViewBag.SearchString = searchstr;
                if (SearchById)
                    query = query.Where(r => r.OidcGroupId == searchstr);
                else
                {
                    string qs = searchstr.ToUpper();
#pragma warning disable CS8602 // Разыменование вероятной пустой ссылки.
                    query = query.Where(r => r.OidcGroupName.StartsWith(qs));
#pragma warning restore CS8602 // Разыменование вероятной пустой ссылки.
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
                return View(new List<OidcGroupDto>());
            }
            if (SearchById)
            {
                query = query.OrderBy(r => r.OidcGroupId);
            }
            else
            {
                query = query.OrderBy(r => r.OidcGroupName);
            }
            if (pager.CurrentPage > 1)
            {

                query = query.Skip((pager.CurrentPage - 1) * pager.PageSize);
            }
            ViewBag.Pager = pager;
            return View(await query.AsNoTracking().Take(pager.PageSize).Select(itm => new OidcGroupDto()
            {
                OidcGroupId = itm.OidcGroupId,
                OidcGroupName = itm.OidcGroupName,
                OidcGroupDisplayName = itm.OidcGroupDisplayName,
            }).ToListAsync());
        }

        // POST: OidcUserGroups/Create
        // To protect from overposting attacks, enable the specific properties you want to bind to.
        // For more details, see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create(string userid, List<string> oidcgroupids)
        {
            if (string.IsNullOrEmpty(userid)) userid = "";
            if ((!string.IsNullOrEmpty(userid)) && (oidcgroupids != null))
            {
                OidcIdentityUser? user = await _userManager.FindByIdAsync(userid);
                if (user != null)
                {
                    bool dosave = false;
                    foreach (var gid in oidcgroupids)
                    {
                        if(! (await _context.OidcUserGroups.AnyAsync(p => p.OidcGroupId == gid && p.OidcUserId == userid)))
                        {
                            string tgid = gid;
                            OidcUserGroup itm = new () { OidcUserId = userid, OidcGroupId = tgid };
                            _context.Add(itm);
                            dosave = true;
                        }
                    }
                    if(dosave)
                    {
                        try
                        {
                            await _context.SaveChangesAsync();
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
                            _logger.LogInformation("Could not Add a User Groups with user ID:" + userid + ": " + sb.ToString());
                        }
                    }
                }
            }
            return RedirectToAction(nameof(Index), new { @userid = userid });
        }
    }
}
