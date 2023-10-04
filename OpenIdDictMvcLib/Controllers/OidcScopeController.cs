using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
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
    public class OidcScopeController : Controller
    {
        private readonly ApplicationDbContext _context;
        UserManager<OidcIdentityUser> _userManager;
        ILogger<OidcScopeDto> _logger;
        private readonly IStringLocalizer<OidcScopeLocalizerResource> _sharedLocalizer;
        public OidcScopeController(ApplicationDbContext context,
            UserManager<OidcIdentityUser> userManager,
            ILogger<OidcScopeDto> logger, 
            IStringLocalizer<OidcScopeLocalizerResource> SharedLocalizer)
        {
            _context = context;
            _userManager = userManager;
            _logger = logger;
            _sharedLocalizer = SharedLocalizer;
        }

        public async Task<IActionResult> Index(string idtype, string prntid)
        {
            IList<OidcScopeDto>? scopes = null;
            if (idtype == "user")
            {
                var user = await _userManager.FindByIdAsync(prntid);
                if (user == null) { return NotFound(); }
                scopes = await _context.OidcUserScopes.Where(p=>p.OidcUserId == user.Id).Select(itm=> new OidcScopeDto()
                {
                    OidcParentId = itm.OidcUserId,
                    OidcAppName = itm.OidcAppName,
                    OidcScopes = itm.OidcScopes,
                    OidcAudiences = itm.OidcAudiences,
                }).ToListAsync();
            }
            else if (idtype == "group")
            {
                var group = await _context.OidcGroups.Where(p=>p.OidcGroupId == prntid).FirstOrDefaultAsync();
                if (group == null) { return NotFound(); }
                scopes = await _context.OidcGroupScopes.Where(p => p.OidcGroupId == group.OidcGroupId).Select(itm => new OidcScopeDto()
                {
                    OidcParentId = itm.OidcGroupId,
                    OidcAppName = itm.OidcAppName,
                    OidcScopes = itm.OidcScopes,
                    OidcAudiences = itm.OidcAudiences,
                }).ToListAsync();
            }
            if (scopes == null) { return NotFound(); }
            ViewBag.IdType = idtype;
            ViewBag.PrntId = prntid;
            return View(scopes);
        }

        // GET: OidcScope/Create
        public IActionResult Create(string idtype, string prntid)
        {

            if (!string.IsNullOrEmpty(idtype))
                ViewBag.IdType = idtype;
            if (!string.IsNullOrEmpty(prntid))
                ViewBag.PrntId = prntid;
            OidcScopeDto scopeDto = new()
            {
                OidcParentId = prntid,
                OidcAppName = null,
                OidcScopes = null,
                OidcAudiences = null,
            };
            return View(scopeDto);
        }

        // POST: OidcScope/Create
        // To protect from overposting attacks, enable the specific properties you want to bind to.
        // For more details, see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create(string idtype, string prntid, [Bind("OidcParentId, OidcAppName, OidcScopes")] OidcScopeDto scopeDto)
        {
            if (ModelState.IsValid)
            {
                if (ModelState.IsValid)
                {
                    if (idtype == "user")
                    {
                        var user = await _userManager.FindByIdAsync(prntid);
                        if (user == null)
                        {
                            ModelState.AddModelError("UserId", _sharedLocalizer["Failed to find user by id:"] + prntid);
                        }
                        else
                        {
                            OidcUserScope uscope = new OidcUserScope() { OidcUserId=user.Id, OidcAppName = scopeDto.OidcAppName, OidcScopes = scopeDto.OidcScopes, OidcAudiences = scopeDto.OidcAudiences };
                            _context.OidcUserScopes.Add(uscope);
                            try
                            {
                                await _context.SaveChangesAsync();
                                return RedirectToAction(nameof(Index), new { idtype = idtype, prntid = prntid });
                            } catch (Exception ex)
                            {
                                Exception? wex = ex;
                                StringBuilder sb = new();
                                while (wex != null)
                                {
                                    sb.Append(wex.Message);
                                    wex = wex.InnerException;
                                }
                                _logger.LogInformation("Could not Create a User Scope with ID:" + uscope.OidcUserId + " " + "and a name:" + uscope.OidcAppName + ": " + sb.ToString());
                                ModelState.AddModelError("Create", sb.ToString());
                            }

                        }
                    }
                    else if (idtype == "group")
                    {
                        var group = await _context.OidcGroups.Where(p => p.OidcGroupId == prntid).FirstOrDefaultAsync();
                        if (group == null)
                        {
                            ModelState.AddModelError("GroupId", _sharedLocalizer["Failed to find Group by id:"] + prntid);
                        }
                        else
                        {
                            OidcGroupScope gscope = new OidcGroupScope() { OidcGroupId = group.OidcGroupId, OidcAppName = scopeDto.OidcAppName, OidcScopes = scopeDto.OidcScopes, OidcAudiences = scopeDto.OidcAudiences };
                            _context.OidcGroupScopes.Add(gscope);
                            try
                            {
                                await _context.SaveChangesAsync();
                                return RedirectToAction(nameof(Index), new { idtype = idtype, prntid = prntid });
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
                                _logger.LogInformation("Could not Create a Group Scope with ID:" + gscope.OidcGroupId + " " + "and a name:" + gscope.OidcAppName + ": " + sb.ToString());
                                ModelState.AddModelError("Create", sb.ToString());
                            }

                        }
                    }
                }
            }

            if (!string.IsNullOrEmpty(idtype))
                ViewBag.IdType = idtype;
            if (!string.IsNullOrEmpty(prntid))
                ViewBag.PrntId = prntid;

            return View(scopeDto);
        }

        // GET: OidcScope/Create
        public async Task<IActionResult> Edit(string idtype, string prntid, string oidcappname)
        {

            if (!string.IsNullOrEmpty(idtype))
                ViewBag.IdType = idtype;
            if (!string.IsNullOrEmpty(prntid))
                ViewBag.PrntId = prntid;
            if (!string.IsNullOrEmpty(oidcappname))
                ViewBag.AppName = oidcappname;
            OidcScopeDto? scopeDto = null;
            if (idtype == "user")
            {
                scopeDto = await _context.OidcUserScopes.Where(s => s.OidcUserId == prntid && s.OidcAppName == oidcappname).
                    Select(itm => new OidcScopeDto {
                    OidcParentId = itm.OidcUserId,
                    OidcAppName = itm.OidcAppName,
                    OidcScopes = itm.OidcScopes,
                    OidcAudiences = itm.OidcAudiences,
                    }).FirstOrDefaultAsync();
            } else if (idtype == "group")
            {
                scopeDto = await _context.OidcGroupScopes.Where(s => s.OidcGroupId == prntid && s.OidcAppName == oidcappname).
                    Select(itm => new OidcScopeDto
                    {
                        OidcParentId = itm.OidcGroupId,
                        OidcAppName = itm.OidcAppName,
                        OidcScopes = itm.OidcScopes,
                        OidcAudiences = itm.OidcAudiences,
                    }).FirstOrDefaultAsync();

            }
            if(scopeDto == null) { return NotFound(); }
            return View(scopeDto);
        }

        // POST: OidcScope/Create
        // To protect from overposting attacks, enable the specific properties you want to bind to.
        // For more details, see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Edit(string idtype, string prntid, string oidcappname, [Bind("OidcParentId, OidcAppName, OidcScopes")] OidcScopeDto scopeDto)
        {
            if (ModelState.IsValid)
            {
                if (ModelState.IsValid)
                {
                    if (idtype == "user")
                    {
                        var uscope = await _context.OidcUserScopes.Where(s => s.OidcUserId == prntid && s.OidcAppName == scopeDto.OidcAppName).FirstOrDefaultAsync();
                        if (uscope == null)
                        {
                            return NotFound();  
                        }
                        uscope.OidcScopes = scopeDto.OidcScopes;
                        await _context.SaveChangesAsync();
                        try
                        {
                            await _context.SaveChangesAsync();
                            return RedirectToAction(nameof(Index), new { idtype = idtype, prntid = prntid });
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
                            _logger.LogInformation("Could not Create a Group Scope with ID:" + uscope.OidcUserId + " " + "and a name:" + uscope.OidcAppName + ": " + sb.ToString());
                            ModelState.AddModelError("Edit", sb.ToString());
                        }
                    }
                    else if (idtype == "group")
                    {
                        var gscope = await _context.OidcGroupScopes.Where(s => s.OidcGroupId == prntid && s.OidcAppName == scopeDto.OidcAppName).FirstOrDefaultAsync();
                        if (gscope == null)
                        {
                            return NotFound();
                        }
                        gscope.OidcScopes = scopeDto.OidcScopes;
                        try
                        {
                            await _context.SaveChangesAsync();
                            return RedirectToAction(nameof(Index), new { idtype = idtype, prntid = prntid });
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
                            _logger.LogInformation("Could not Create a Group Scope with ID:" + gscope.OidcGroupId + " " + "and a name:" + gscope.OidcAppName + ": " + sb.ToString());
                            ModelState.AddModelError("Edit", sb.ToString());
                        }
                    }
                }
            }
            if (!string.IsNullOrEmpty(idtype))
                ViewBag.IdType = idtype;
            if (!string.IsNullOrEmpty(prntid))
                ViewBag.PrntId = prntid;
            if (!string.IsNullOrEmpty(oidcappname))
                ViewBag.AppName = oidcappname;
            return View(scopeDto);
        }

        // GET: OidcScope/Details/
        public async Task<IActionResult> Details(string idtype, string prntid, string oidcappname)
        {

            if (!string.IsNullOrEmpty(idtype))
                ViewBag.IdType = idtype;
            if (!string.IsNullOrEmpty(prntid))
                ViewBag.PrntId = prntid;
            if (!string.IsNullOrEmpty(oidcappname))
                ViewBag.AppName = oidcappname;
            OidcScopeDto? scopeDto = null;
            if (idtype == "user")
            {
                scopeDto = await _context.OidcUserScopes.Where(s => s.OidcUserId == prntid && s.OidcAppName == oidcappname).
                    Select(itm => new OidcScopeDto
                    {
                        OidcParentId = itm.OidcUserId,
                        OidcAppName = itm.OidcAppName,
                        OidcScopes = itm.OidcScopes,
                        OidcAudiences = itm.OidcAudiences,
                    }).FirstOrDefaultAsync();
            }
            else if (idtype == "group")
            {
                scopeDto = await _context.OidcGroupScopes.Where(s => s.OidcGroupId == prntid && s.OidcAppName == oidcappname).
                    Select(itm => new OidcScopeDto
                    {
                        OidcParentId = itm.OidcGroupId,
                        OidcAppName = itm.OidcAppName,
                        OidcScopes = itm.OidcScopes,
                        OidcAudiences = itm.OidcAudiences,
                    }).FirstOrDefaultAsync();

            }
            if (scopeDto == null) { return NotFound(); }
            return View(scopeDto);
        }

        // GET: OidcScope/Delete/
        public async Task<IActionResult> Delete(string idtype, string prntid, string oidcappname)
        {

            if (!string.IsNullOrEmpty(idtype))
                ViewBag.IdType = idtype;
            if (!string.IsNullOrEmpty(prntid))
                ViewBag.PrntId = prntid;
            if (!string.IsNullOrEmpty(oidcappname))
                ViewBag.AppName = oidcappname;
            OidcScopeDto? scopeDto = null;
            if (idtype == "user")
            {
                scopeDto = await _context.OidcUserScopes.Where(s => s.OidcUserId == prntid && s.OidcAppName == oidcappname).
                    Select(itm => new OidcScopeDto
                    {
                        OidcParentId = itm.OidcUserId,
                        OidcAppName = itm.OidcAppName,
                        OidcScopes = itm.OidcScopes,
                        OidcAudiences = itm.OidcAudiences,
                    }).FirstOrDefaultAsync();
            }
            else if (idtype == "group")
            {
                scopeDto = await _context.OidcGroupScopes.Where(s => s.OidcGroupId == prntid && s.OidcAppName == oidcappname).
                    Select(itm => new OidcScopeDto
                    {
                        OidcParentId = itm.OidcGroupId,
                        OidcAppName = itm.OidcAppName,
                        OidcScopes = itm.OidcScopes,
                        OidcAudiences = itm.OidcAudiences,
                    }).FirstOrDefaultAsync();

            }
            if (scopeDto == null) { return NotFound(); }
            return View(scopeDto);
        }

        // POST: OidcScope/Delete/5
        [HttpPost, ActionName("Delete")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteConfirmed(string idtype, string prntid, string oidcappname)
        {
            if (!string.IsNullOrEmpty(idtype))
                ViewBag.IdType = idtype;
            if (!string.IsNullOrEmpty(prntid))
                ViewBag.PrntId = prntid;
            if (!string.IsNullOrEmpty(oidcappname))
                ViewBag.AppName = oidcappname;
            OidcScopeDto? scopeDto = null;
            if (idtype == "user")
            {
                var uscope = await _context.OidcUserScopes.Where(s => s.OidcUserId == prntid && s.OidcAppName == oidcappname).FirstOrDefaultAsync();
                if(uscope == null) { return NotFound(); };
                _context.Remove(uscope);
                try
                {
                    await _context.SaveChangesAsync();
                    return RedirectToAction(nameof(Index), new { idtype = idtype, prntid = prntid });
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
                    _logger.LogInformation("Could not Delete a User Scope with ID:" + uscope.OidcUserId + " " + "and a name:" + uscope.OidcAppName + ": " + sb.ToString());
                    ModelState.AddModelError("Delete", sb.ToString());
                }
                scopeDto = new OidcScopeDto()
                {
                    OidcParentId = uscope.OidcUserId,
                    OidcAppName = uscope.OidcAppName,
                    OidcScopes = uscope.OidcScopes,
                    OidcAudiences = uscope.OidcAudiences
                };
            }
            else if (idtype == "group")
            {
                var gscope = await _context.OidcGroupScopes.Where(s => s.OidcGroupId == prntid && s.OidcAppName == oidcappname).FirstOrDefaultAsync();
                if (gscope == null) { return NotFound(); };
                _context.Remove(gscope);
                try
                {
                    await _context.SaveChangesAsync();
                    return RedirectToAction(nameof(Index), new { idtype = idtype, prntid = prntid });
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
                    _logger.LogInformation("Could not Delete a Group Scope with ID:" + gscope.OidcGroupId + " " + "and a name:" + gscope.OidcAppName + ": " + sb.ToString());
                    ModelState.AddModelError("Delete", sb.ToString());
                }
                scopeDto = new OidcScopeDto()
                {
                    OidcParentId = gscope.OidcGroupId,
                    OidcAppName = gscope.OidcAppName,
                    OidcScopes = gscope.OidcScopes,
                    OidcAudiences = gscope.OidcAudiences
                };

            }
            if (scopeDto == null) { return NotFound(); }
            return View(scopeDto);

        }
    }
}
