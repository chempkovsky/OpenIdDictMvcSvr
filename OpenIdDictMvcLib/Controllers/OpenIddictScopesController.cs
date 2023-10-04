using System.Globalization;
using System.Text;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Localization;
using OpenIddict.Abstractions;
using OpenIdDictMvcContext.Data;
using OpenIdDictMvcLib.Dto;
using OpenIdDictMvcLib.Helpers;
using OpenIdDictMvcLib.Localizers;
using Microsoft.Extensions.Logging;
using Microsoft.AspNetCore.Authorization;

namespace OpenIdDictMvcLib.Controllers
{
    [Authorize(Roles = $"{OidcIdentityConsts.AdminRoleName}")]
    public class OpenIddictScopesController : Controller
    {
        private readonly ApplicationDbContext _context;
        private readonly IOpenIddictScopeManager _scopeManager;
        private readonly IStringLocalizer<OpenIddictScopeLocalizerResource> _sharedLocalizer;
        private readonly ILogger<OpenIddictScopeDescriptorDto> _logger;

        public OpenIddictScopesController(ApplicationDbContext context, 
            IOpenIddictScopeManager scopeManager,
            ILogger<OpenIddictScopeDescriptorDto> logger,
            IStringLocalizer<OpenIddictScopeLocalizerResource> sharedLocalizer)
        {
            //OpenIddictTokenDescriptor? d = null;
            //OpenIddictAuthorizationDescriptor? d = null;
            _context = context;
            _scopeManager = scopeManager;
            _sharedLocalizer = sharedLocalizer;
            _logger = logger;
        }

        // GET: OpenIddictScopes
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
                new SelectListItem(){ Text = _sharedLocalizer["Filter by Scope Name"], Value = "1", Selected = SearchById == 1 },
            };
            if (!string.IsNullOrEmpty(searchstr))
            {
                ViewBag.SearchString = searchstr;
                Object? scope = SearchById switch
                {
                    1 => scope = (await _scopeManager.FindByNameAsync(searchstr)),
                    _ => scope = (await _scopeManager.FindByIdAsync(searchstr))
                };
                List<OpenIddictScopeDescriptorDto> rslt = new();
                if (scope != null)
                {
                    rslt.Add(new OpenIddictScopeDescriptorDto()
                    {
                        ScopeId = await _scopeManager.GetIdAsync(scope),
                        Name = await _scopeManager.GetNameAsync(scope),
                        DisplayName = await _scopeManager.GetDisplayNameAsync(scope),
                        Description = await _scopeManager.GetDescriptionAsync(scope),
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
            var dbst = _context.Set<OidcScope>();
            if (dbst == null)
            {
                return Problem(_sharedLocalizer["Entity set 'ApplicationDbContext.OpenIddictEntityFrameworkCoreScope' is null."]);
            }
            var query = dbst.AsNoTracking();
            int total = (int)await _scopeManager.CountAsync();
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
                return View(new List<OpenIddictScopeDescriptorDto>());
            }
            if (pager.CurrentPage > 1)
            {

                query = query.OrderBy(a => a.Id).Skip((pager.CurrentPage - 1) * pager.PageSize);
            }
            ViewBag.Pager = pager;
            return View(await query.AsNoTracking().Take(pager.PageSize).Select(itm => new OpenIddictScopeDescriptorDto()
            {
                ScopeId = itm.Id,
                Name = itm.Name,
                DisplayName = itm.DisplayName,
                Description = itm.Description,
            }).ToListAsync());
        }

        // GET: OpenIddictScopes/Create
        public IActionResult Create()
        {
            ViewBag.ResourcesList = Array.Empty<string>();
            ViewBag.DisplayNames = new List<KeyValuePair<string, string>>();
            return View();
        }
        internal void CheckCollection(OpenIddictScopeDescriptorDto descriptorDto)
        {
            bool errNotAdded = true;
            if (descriptorDto.Resources != null)
            {
                foreach (var resource in descriptorDto.Resources)
                {
                    if (string.IsNullOrEmpty(resource))
                    {
                        if (errNotAdded)
                        {
                            ModelState.AddModelError("Resources", _sharedLocalizer["Not all Resources Fields are populated with data."]);
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

        // POST: OpenIddictScopes/Create
        // To protect from overposting attacks, enable the specific properties you want to bind to.
        // For more details, see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create([Bind("Name,DisplayName,Description,Resources,DisplayNames")] OpenIddictScopeDescriptorDto descriptorDto)
        {
            if (ModelState.IsValid)
            {
                CheckCollection(descriptorDto);
                if (ModelState.IsValid)
                {
                    OpenIddictScopeDescriptor descriptor = new()
                    {
                        Name = descriptorDto.Name,
                        DisplayName = descriptorDto.DisplayName,
                        Description = descriptorDto.Description,
                    };
                    if (descriptorDto.Resources != null)
                    {
                        foreach (var resource in descriptorDto.Resources)
                        {
                            descriptor.Resources.Add(resource);
                        }
                    }
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
                        try
                        {
                            var rslt = await _scopeManager.CreateAsync(descriptor);
                            _logger.LogInformation("Created a new Scope named:" + descriptor.Name + ": " + descriptor.DisplayName);
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
                                string errorMessage = _sharedLocalizer["Could not create new Scope"] + ": " + sb.ToString();
                                ModelState.AddModelError("Create", errorMessage);
                                _logger.LogInformation("Could not create new Scope: " + sb.ToString());
                            }
                        }
                    }

                }
            }
            ViewBag.ResourcesList = descriptorDto.Resources ?? Array.Empty<string>();
            ViewBag.DisplayNames = descriptorDto.DisplayNames ?? (new List<KeyValuePair<string, string>>());
            return View(descriptorDto);
        }

        internal async Task<OpenIddictScopeDescriptorDto?> PrepareDto(string scopeid)
        {
            var scope = await _scopeManager.FindByIdAsync(scopeid);
            if (scope == null)
            {
                return null;
            }
            OpenIddictScopeDescriptor descriptor = new();
            await _scopeManager.PopulateAsync(descriptor, scope);
            OpenIddictScopeDescriptorDto descriptorDto = new()
            {
                ScopeId = await _scopeManager.GetIdAsync(scope),
                Name = descriptor.Name,
                DisplayName = descriptor.DisplayName,
                Description = descriptor.Description,

            };
            if (descriptor.Resources.Count > 0)
            {
                descriptorDto.Resources = descriptor.Resources.ToArray();
            }
            if (descriptor.DisplayNames.Count > 0)
            {
                descriptorDto.DisplayNames = new List<KeyValuePair<string, string>>();
                foreach (var dn in descriptor.DisplayNames)
                {
                    descriptorDto.DisplayNames.Add(new(dn.Key.Name, dn.Value));
                }
            }
            ViewBag.ResourcesList = descriptorDto.Resources ?? Array.Empty<string>();
            ViewBag.DisplayNames = descriptorDto.DisplayNames ?? (new List<KeyValuePair<string, string>>());
            return descriptorDto;
        }

        // GET: OpenIddictScopes/Edit/5
        public async Task<IActionResult> Edit(string scopeid)
        {
            if (scopeid == null)
            {
                return NotFound();
            }

            try
            {
                OpenIddictScopeDescriptorDto? descriptorDto = await PrepareDto(scopeid);
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
                return Problem(_sharedLocalizer["Could not find Scope by ID."] + "Id=" + scopeid + sb.ToString());
            }
        }

        // POST: OpenIddictScopes/Edit/5
        // To protect from overposting attacks, enable the specific properties you want to bind to.
        // For more details, see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Edit(string scopeid, [Bind("ScopeId,Name,DisplayName,Description,Resources,DisplayNames")] OpenIddictScopeDescriptorDto descriptorDto)
        {
            if (scopeid != descriptorDto.ScopeId)
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
                        OpenIddictScopeDescriptor descriptor = new();
                        var scope = await _scopeManager.FindByIdAsync(scopeid);
                        if (scope == null)
                        {
                            return NotFound();
                        }
                        await _scopeManager.PopulateAsync(descriptor, scope);
                        descriptor.Name = descriptorDto.Name;
                        descriptor.DisplayName = descriptorDto.DisplayName;
                        descriptor.Description = descriptorDto.Description;
                        descriptor.Resources.Clear();
                        if (descriptorDto.Resources != null)
                        {
                            foreach (var resource in descriptorDto.Resources)
                            {
                                descriptor.Resources.Add(resource);
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
                            await _scopeManager.UpdateAsync(scope, descriptor);
                            _logger.LogInformation("Updated Scope with Id:" + scopeid + ": " + descriptor.Name + ": " + descriptor.DisplayName);
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
                        string errorMessage = _sharedLocalizer["Could not update Scope with Id:"] + scopeid + ": " + sb.ToString();
                        ModelState.AddModelError("Update", errorMessage);
                        _logger.LogInformation("Could not update Scope with Id:" + scopeid + ": " + sb.ToString());
                    }

                }
            }
            ViewBag.ResourcesList = descriptorDto.Resources ?? Array.Empty<string>();
            ViewBag.DisplayNames = descriptorDto.DisplayNames ?? (new List<KeyValuePair<string, string>>());
            return View(descriptorDto);
        }

        // GET: OpenIddictScopes/Details/5
        public async Task<IActionResult> Details(string scopeid)
        {
            if (scopeid == null)
            {
                return NotFound();
            }

            try
            {
                OpenIddictScopeDescriptorDto? descriptorDto = await PrepareDto(scopeid);
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
                return Problem(_sharedLocalizer["Could not find Scope by ID."] + "Id=" + scopeid + sb.ToString());
            }
        }

        // GET: OpenIddictScopes/Delete/5
        public async Task<IActionResult> Delete(string scopeid)
        {
            if (scopeid == null)
            {
                return NotFound();
            }

            try
            {
                OpenIddictScopeDescriptorDto? descriptorDto = await PrepareDto(scopeid);
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
                return Problem(_sharedLocalizer["Could not find Scope by ID."] + "Id=" + scopeid + sb.ToString());
            }
        }

        // POST: OpenIddictScopes/Delete/5
        [HttpPost, ActionName("Delete")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteConfirmed(string scopeid)
        {
            if (scopeid == null)
            {
                return NotFound();
            }
            try
            {
                var scope = await _scopeManager.FindByIdAsync(scopeid);
                if (scope == null)
                {
                    return NotFound();
                }
                await _scopeManager.DeleteAsync(scope);
                _logger.LogInformation("Deleted Scope with Id:" + scopeid);
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
                return Problem(_sharedLocalizer["Could not delete Scope by ID."] + "Id=" + scopeid + sb.ToString());
            }
            return RedirectToAction(nameof(Index));
        }
    }
}
