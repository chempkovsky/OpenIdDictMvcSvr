using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Localization;
using OpenIdDictMvcContext.Data;
using OpenIdDictMvcLib.Dto;
using OpenIdDictMvcLib.Localizers;
using Microsoft.Extensions.Logging;

namespace OpenIdDictMvcLib.Controllers
{
    public class RolesController : Controller
    {
        private readonly RoleManager<OidcIdentityRole> _roleManager;
        private readonly ILogger<IdentityRoleDto> _logger;
        private readonly IStringLocalizer<RoleLocalizerResource> _sharedLocalizer;

        public RolesController(RoleManager<OidcIdentityRole> roleManager,
            ILogger<IdentityRoleDto> logger,
            IStringLocalizer<RoleLocalizerResource> SharedLocalizer)
        {
            _logger = logger;
            _roleManager = roleManager;
            _sharedLocalizer = SharedLocalizer;
        }

        // GET: Roles
        public async Task<IActionResult> Index(string? searchby=null, string? searchstr = null, int? currpg=null)
        {
            PageDto pager = new () { PageSize = 10 };
            if (currpg.HasValue)
            {
                pager.CurrentPage = currpg.Value;
            } else
            {
                pager.CurrentPage = 1;
            }

            bool SearchById = true;
            if (!string.IsNullOrEmpty(searchby))
            {
                SearchById = searchby == "0";
            }
            ViewBag.SearchBy =  new List<SelectListItem>() { 
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
            } else
            {
                ViewBag.SearchString = "";
            }
            int total = await query.CountAsync();
            pager.PageCount = total / pager.PageSize;
            if (pager.PageCount * pager.PageSize < total) pager.PageCount++;
            if ((pager.CurrentPage > pager.PageCount) || (pager.CurrentPage < 1)) pager.CurrentPage = 1;
            pager.PrintFrom = pager.CurrentPage-2;
            if (pager.PrintFrom < 1) pager.PrintFrom = 1;
            pager.PrintTo = pager.PrintFrom + 5;
            if (pager.PrintTo > pager.PageCount) pager.PrintTo = pager.PageCount;
            ViewBag.SearchById = SearchById ? "0" : "1";
            if (total < 1)
            {
                ViewBag.Pager = pager;
                return View(new List<IdentityRoleDto>());
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
            return View(await query.AsNoTracking().Take(pager.PageSize).Select(itm => new IdentityRoleDto()
                    {
                        Id = itm.Id,
                        Name = itm.Name,
                        NormalizedName = itm.NormalizedName,
                        ConcurrencyStamp = itm.ConcurrencyStamp
                    }).ToListAsync());
        }

        // GET: Roles/Details/5
        public async Task<IActionResult> Details(string id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var identityRoleDto = await _roleManager.Roles.Where(m => m.Id == id).Select(itm => new IdentityRoleDto()
            {
                Id = itm.Id,
                Name = itm.Name,
                NormalizedName = itm.NormalizedName,
                ConcurrencyStamp = itm.ConcurrencyStamp
            }).FirstOrDefaultAsync();

            if (identityRoleDto == null)
            {
                return NotFound();
            }

            return View(identityRoleDto);
        }

        // GET: Roles/Create
        public IActionResult Create()
        {
            return View();
        }

        // POST: Roles/Create
        // To protect from overposting attacks, enable the specific properties you want to bind to.
        // For more details, see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create([Bind("Name")] NewRoleDto newRoleDto)
        {
            if (ModelState.IsValid)
            {
                OidcIdentityRole entityToAdd = new () { Name = newRoleDto.Name };
                IdentityResult rslt = await _roleManager.CreateAsync(entityToAdd);
                if (rslt.Succeeded)
                {
                    _logger.LogInformation("Created a new role named:" + newRoleDto.Name);
                    return RedirectToAction(nameof(Index));
                }
                string ExceptionStr = "";
                if (rslt.Errors != null)
                {
                    foreach (var e in rslt.Errors)
                        ExceptionStr = e.Code + ":" + e.Description;
                }
                _logger.LogInformation("Could not create new role with name:" + newRoleDto.Name + ": " + ExceptionStr);
                throw new InvalidOperationException(ExceptionStr);
            }
            return View(newRoleDto);
        }

        // GET: Roles/Edit/5
        public async Task<IActionResult> Edit(string id)
        {
            if (id == null)
            {
                return NotFound();
            }
            var identityRoleDto = await _roleManager.Roles.Where(m => m.Id == id).Select(itm => new IdentityRoleDto()
            {
                Id = itm.Id,
                Name = itm.Name,
                NormalizedName = itm.NormalizedName,
                ConcurrencyStamp = itm.ConcurrencyStamp
            }).FirstOrDefaultAsync();
            if (identityRoleDto == null)
            {
                return NotFound();
            }
            return View(identityRoleDto);
        }

        // POST: Roles/Edit/5
        // To protect from overposting attacks, enable the specific properties you want to bind to.
        // For more details, see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Edit(string id, [Bind("Id,Name,NormalizedName,ConcurrencyStamp")] IdentityRoleDto identityRoleDto)
        {
            if (id != identityRoleDto.Id)
            {
                return NotFound();
            }

            if (ModelState.IsValid)
            {
                try
                {
                    var aRole = await _roleManager.FindByIdAsync(identityRoleDto.Id);
                    if(aRole == null)
                    {
                        return NotFound();
                    }
                    aRole.Name = identityRoleDto.Name;
                    aRole.ConcurrencyStamp = identityRoleDto.ConcurrencyStamp;
                    var rslt = await _roleManager.UpdateAsync(aRole);
                   if (rslt.Succeeded) {
                        _logger.LogInformation("Updated a role with ID:" + identityRoleDto.Id + " "+ "and a new name:" + identityRoleDto.Name);

                    } else
                    {
                        string ExceptionStr = "";
                        if (rslt.Errors != null)
                        {
                            foreach (var e in rslt.Errors)
                                ExceptionStr = e.Code + ":" + e.Description;
                        }
                        _logger.LogInformation("Could not update a role with ID:" + identityRoleDto.Id + " " + "and a new name:" + identityRoleDto.Name + ": " + ExceptionStr);
                        throw new InvalidOperationException(ExceptionStr);
                    }
                }
                catch (DbUpdateConcurrencyException)
                {
                    if (!(await IdentityRoleDtoExists(identityRoleDto.Id)))
                    {
                        return NotFound();
                    }
                    else
                    {
                        throw;
                    }
                }
                return RedirectToAction(nameof(Index));
            }
            return View(identityRoleDto);
        }

        // GET: Roles/Delete/5
        public async Task<IActionResult> Delete(string id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var identityRoleDto = await _roleManager.Roles.Where(m => m.Id == id).Select(itm => new IdentityRoleDto()
            {
                Id = itm.Id,
                Name = itm.Name,
                NormalizedName = itm.NormalizedName,
                ConcurrencyStamp = itm.ConcurrencyStamp
            }).FirstOrDefaultAsync();
            if (identityRoleDto == null)
            {
                return NotFound();
            }

            return View(identityRoleDto);
        }

        // POST: Roles/Delete/5
        [HttpPost, ActionName("Delete")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteConfirmed(string id)
        {
            //if (_context.IdentityRoleDto == null)
            //{
            //    return Problem("Entity set 'ApplicationDbContext.IdentityRoleDto'  is null.");
            //}
            var aRole = await _roleManager.FindByIdAsync(id);
            if (aRole != null)
            {
                var rslt = await _roleManager.DeleteAsync(aRole);
                if (rslt.Succeeded)
                {
                    _logger.LogInformation("Deleted a role with ID:" + aRole.Id + " " + "and a name:" + aRole.Name);
                } else
                {
                    string ExceptionStr = "";
                    if (rslt.Errors != null)
                    {
                        foreach (var e in rslt.Errors)
                            ExceptionStr = e.Code + ":" + e.Description;
                    }
                    _logger.LogInformation("Could not delete a role with ID:" + aRole.Id + " " + "and a name:" + aRole.Name + ": " + ExceptionStr);
                    throw new InvalidOperationException(ExceptionStr);
                }
            }
            return RedirectToAction(nameof(Index));
        }

        private async Task<bool> IdentityRoleDtoExists(string id)
        {
          return (await _roleManager.Roles.AnyAsync(e => e.Id == id));
        }
    }
}
