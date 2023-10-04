using Microsoft.AspNetCore.Authorization;
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
    public class OidcGroupsController : Controller
    {
        private readonly ApplicationDbContext _context;
        private readonly IStringLocalizer<OidcGroupLocalizerResource> _sharedLocalizer;
        private readonly ILogger<OidcGroupDto> _logger;

        public OidcGroupsController(ApplicationDbContext context, 
            ILogger<OidcGroupDto> logger,
            IStringLocalizer<OidcGroupLocalizerResource> sharedLocalizer)
        {
            _context = context;
            _logger = logger;
            _sharedLocalizer = sharedLocalizer;
        }

        // GET: OidcGroups
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
                OidcGroupDisplayName = itm.OidcGroupDisplayName
            }).ToListAsync());
        }
        // GET: OidcGroups/Create
        public IActionResult Create()
        {
            return View();
        }
        // POST: OidcGroups/Create
        // To protect from overposting attacks, enable the specific properties you want to bind to.
        // For more details, see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create([Bind("OidcGroupName,OidcGroupDisplayName")] OidcGroupDto oidcGroupDto)
        {
            if (ModelState.IsValid)
            {
                var itm = new OidcGroup() { OidcGroupName = oidcGroupDto.OidcGroupName, OidcGroupDisplayName = oidcGroupDto.OidcGroupDisplayName };
                _context.Add(itm);
                try
                {
                    await _context.SaveChangesAsync();
                    _logger.LogInformation("Created a new Group named:" + oidcGroupDto.OidcGroupName);
                    return RedirectToAction(nameof(Index));
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
                    _logger.LogInformation("Could not create a Group with ID:" + itm.OidcGroupId + " " + "and a name:" + itm.OidcGroupName + ": " + sb.ToString());
                    ModelState.AddModelError("Create", sb.ToString());
                }
            }
            return View(oidcGroupDto);
        }


        // GET: OidcGroups/Edit/5
        public async Task<IActionResult> Edit(string oidcgroupid)
        {
            if (oidcgroupid == null || _context.OidcGroups == null)
            {
                return NotFound();
            }

            var oidcGroupDto = await _context.OidcGroups.Where(p => p.OidcGroupId == oidcgroupid).Select(itm => new OidcGroupDto()
            {
                OidcGroupId = itm.OidcGroupId,
                OidcGroupName = itm.OidcGroupName,
                OidcGroupDisplayName = itm.OidcGroupDisplayName
            }).FirstOrDefaultAsync();
            if (oidcGroupDto == null)
            {
                return NotFound();
            }
            return View(oidcGroupDto);
        }
        // POST: OidcGroups/Edit/5
        // To protect from overposting attacks, enable the specific properties you want to bind to.
        // For more details, see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Edit(string oidcgroupid, [Bind("OidcGroupId,OidcGroupName,OidcGroupDisplayName")] OidcGroupDto oidcGroupDto)
        {
            if (oidcgroupid != oidcGroupDto.OidcGroupId)
            {
                return NotFound();
            }

            if (ModelState.IsValid)
            {
                try
                {
                    var group = await _context.OidcGroups.Where(p => p.OidcGroupId == oidcgroupid).FirstOrDefaultAsync();
                    if (group == null)
                    {
                        return NotFound();
                    }
                    group.OidcGroupDisplayName = oidcGroupDto.OidcGroupDisplayName;
                    group.OidcGroupName = oidcGroupDto.OidcGroupName;
                    await _context.SaveChangesAsync();
                    _logger.LogInformation("Updated a Group with ID:" + group.OidcGroupId + " " + "and a name:" + group.OidcGroupName);
                    return RedirectToAction(nameof(Index));
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
                    _logger.LogInformation("Could not Updated a Group with ID:" + oidcGroupDto.OidcGroupId + " " + "and a name:" + oidcGroupDto.OidcGroupName + ": " + sb.ToString());
                    ModelState.AddModelError("Edit", sb.ToString());
                }
                
            }
            return View(oidcGroupDto);
        }

        // GET: OidcGroups/Details/5
        public async Task<IActionResult> Details(string oidcgroupid)
        {
            if (oidcgroupid == null || _context.OidcGroups == null)
            {
                return NotFound();
            }

            var oidcGroupDto = await _context.OidcGroups.Where(p => p.OidcGroupId == oidcgroupid).Select(itm => new OidcGroupDto()
            {
                OidcGroupId = itm.OidcGroupId,
                OidcGroupName = itm.OidcGroupName,
                OidcGroupDisplayName = itm.OidcGroupDisplayName
            }).FirstOrDefaultAsync();
            if (oidcGroupDto == null)
            {
                return NotFound();
            }
            return View(oidcGroupDto);
        }

        // GET: OidcGroups/Delete/5
        public async Task<IActionResult> Delete(string oidcgroupid)
        {
            if (oidcgroupid == null || _context.OidcGroups == null)
            {
                return NotFound();
            }

            var oidcGroupDto = await _context.OidcGroups.Where(p => p.OidcGroupId == oidcgroupid).Select(itm => new OidcGroupDto()
            {
                OidcGroupId = itm.OidcGroupId,
                OidcGroupName = itm.OidcGroupName,
                OidcGroupDisplayName = itm.OidcGroupDisplayName
            }).FirstOrDefaultAsync();
            if (oidcGroupDto == null)
            {
                return NotFound();
            }
            return View(oidcGroupDto);
        }

        // POST: OidcGroups/Delete/5
        [HttpPost, ActionName("Delete")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteConfirmed(string oidcgroupid)
        {
            if (_context.OidcGroups == null)
            {
                return Problem("Entity set 'TempDbContext.OidcGroups'  is null.");
            }
            var group = await _context.OidcGroups.Where(p => p.OidcGroupId == oidcgroupid).FirstOrDefaultAsync();
            if (group != null)
            {
                try { 
                    _context.OidcGroups.Remove(group);
                    await _context.SaveChangesAsync();
                    _logger.LogInformation("Deleted a Group with ID:" + group.OidcGroupId + " " + "and a name:" + group.OidcGroupName);
                    return RedirectToAction(nameof(Index));
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
                    _logger.LogInformation("Could not delete a Group with ID:" + group.OidcGroupId + " " + "and a name:" + group.OidcGroupName + ": " + sb.ToString());
                    ModelState.AddModelError("Delete", sb.ToString());
                    View(new OidcGroupDto()
                    {
                        OidcGroupId = group.OidcGroupId,
                        OidcGroupName = group.OidcGroupName,
                        OidcGroupDisplayName = group.OidcGroupDisplayName
                    });
                }
            }
            return RedirectToAction(nameof(Index));
        }


    }
}
