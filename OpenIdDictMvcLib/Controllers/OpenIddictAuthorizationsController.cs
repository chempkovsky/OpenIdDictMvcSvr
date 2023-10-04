using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Localization;
using OpenIddict.Abstractions;
using OpenIdDictMvcContext.Data;
using OpenIdDictMvcLib.Dto;
using System.Text;
using OpenIdDictMvcLib.Localizers;
using Microsoft.Extensions.Logging;
using Microsoft.AspNetCore.Authorization;

namespace OpenIdDictMvcLib.Controllers
{
    [Authorize(Roles = $"{OidcIdentityConsts.AdminRoleName}")]
    public class OpenIddictAuthorizationsController : Controller
    {
        private readonly ApplicationDbContext _context;
        private readonly IOpenIddictAuthorizationManager _authorizationManager;
        private readonly IStringLocalizer<OpenIddictAuthorizationLocalizerResource> _sharedLocalizer;
        private readonly ILogger<OpenIddictAuthorizationDescriptorDto> _logger;

        public OpenIddictAuthorizationsController(ApplicationDbContext context,
                                                IOpenIddictAuthorizationManager authorizationManager,
                                                ILogger<OpenIddictAuthorizationDescriptorDto> logger,
                                                IStringLocalizer<OpenIddictAuthorizationLocalizerResource> sharedLocalizer)
        {
            _context = context;
            _logger = logger;
            _authorizationManager = authorizationManager;
            _sharedLocalizer = sharedLocalizer;
        }

        // GET: OpenIddictAuthorizations
        public async Task<IActionResult> Index(string? appid = null, string? searchby = null, string? searchstr = null, int? currpg = null)
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
                new SelectListItem(){ Text = _sharedLocalizer["Filter by Status"], Value = "1", Selected = SearchById == 1 },
            };

            ViewBag.AppId = appid ?? "";
            ViewBag.SearchString = searchstr ?? "";
            if ( (!string.IsNullOrEmpty(searchstr)) && (SearchById == 0))
            {
                Object? auth = await _authorizationManager.FindByIdAsync(searchstr);
                List<OpenIddictAuthDto> rslt = new();
                if (auth != null)
                {
                    rslt.Add(new OpenIddictAuthDto()
                    {
                        AuthorizationId = await _authorizationManager.GetIdAsync(auth),
                        ApplicationId = await _authorizationManager.GetApplicationIdAsync(auth),
                        CreationDate = await _authorizationManager.GetCreationDateAsync(auth),
                        Status = await _authorizationManager.GetStatusAsync(auth),
                        Subject = await _authorizationManager.GetSubjectAsync(auth),
                        AuthorizationType = await _authorizationManager.GetTypeAsync(auth),
                    });
                }
                pager.PageCount = 0;
                pager.PrintFrom = 1;
                pager.PrintTo = 0;
                ViewBag.Pager = pager;
                pager.CurrentPage = 1;
                return View(rslt);
            }
            var dbst = _context.Set<OidcAuthorization>();
            if (dbst == null)
            {
                return Problem(_sharedLocalizer["Entity set 'ApplicationDbContext.OpenIddictEntityFrameworkCoreAuthorization' is null."]);
            }
            var query = dbst.AsNoTracking();
            if(!string.IsNullOrEmpty(appid))
            {
#pragma warning disable CS8602 // Разыменование вероятной пустой ссылки.
                query = query.Where(a => (a.Application.Id == appid));
#pragma warning restore CS8602 // Разыменование вероятной пустой ссылки.
            }
            if (!string.IsNullOrEmpty(searchstr))
            {
                query = query.Where(a => (a.Status == searchstr));
            }
            int total = (int)await query.CountAsync();
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
                return View(new List<OpenIddictAuthDto>());
            }
            if (pager.CurrentPage > 1)
            {
                query = query.OrderBy(a => a.Id).Skip((pager.CurrentPage - 1) * pager.PageSize);
            }
            ViewBag.Pager = pager;
            return View(await query.AsNoTracking().Take(pager.PageSize).Select(itm => new OpenIddictAuthDto()
            {
                AuthorizationId = itm.Id,
                ApplicationId = itm.Application == null ? null : itm.Application.Id,
                Status = itm.Status,
                Subject = itm.Subject,
                AuthorizationType = itm.Type
            }).ToListAsync());
        }

        internal async Task<OpenIddictAuthorizationDescriptorDto?> PrepareDto(string authorizationid)
        {
            var auth = await _authorizationManager.FindByIdAsync(authorizationid);
            if (auth == null)
            {
                return null;
            }
            OpenIddictAuthorizationDescriptor descriptor = new();
            await _authorizationManager.PopulateAsync(descriptor, auth);
            OpenIddictAuthorizationDescriptorDto descriptorDto = new()
            {
                AuthorizationId = await _authorizationManager.GetIdAsync(auth),
                ApplicationId = descriptor.ApplicationId,
                CreationDate = descriptor.CreationDate,
                Status = descriptor.Status,
                Subject = descriptor.Subject,
                AuthorizationType = descriptor.Type,
            };
            if (descriptor.Scopes.Count > 0)
            {
                descriptorDto.Scopes = descriptor.Scopes.ToArray();
            }
            ViewBag.ScopesList = descriptorDto.Scopes ?? Array.Empty<string>();
            ViewBag.AppId = descriptorDto.ApplicationId;
            return descriptorDto;
        }

        // GET: OpenIddictAuthorizations/Details/5
        public async Task<IActionResult> Details(string authorizationid)
        {
            if (authorizationid == null)
            {
                return NotFound();
            }
            try
            {
                OpenIddictAuthorizationDescriptorDto? descriptorDto = await PrepareDto(authorizationid);
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
                return Problem(_sharedLocalizer["Could not find Authorization by ID."] + "Id=" + authorizationid + sb.ToString());
            }
        }

        // GET: OpenIddictAuthorizations/Delete/5
        public async Task<IActionResult> Delete(string authorizationid)
        {
            if (authorizationid == null)
            {
                return NotFound();
            }
            try
            {
                OpenIddictAuthorizationDescriptorDto? descriptorDto = await PrepareDto(authorizationid);
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
                return Problem(_sharedLocalizer["Could not find Authorization by ID."] + "Id=" + authorizationid + sb.ToString());
            }
        }
        // POST: OpenIddictAuthorizations/Delete/5
        [HttpPost, ActionName("Delete")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteConfirmed(string authorizationid)
        {
            if (authorizationid == null)
            {
                return NotFound();
            }
            string Appid = "";
            try
            {
                var auth = await _authorizationManager.FindByIdAsync(authorizationid);
                if (auth == null)
                {
                    return NotFound();
                }
                Appid = await _authorizationManager.GetApplicationIdAsync(auth) ?? "";
                await _authorizationManager.DeleteAsync(auth);
                _logger.LogInformation("Deleted Authorization with Id:" + authorizationid);
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
                return Problem(_sharedLocalizer["Could not delete Authorization by ID."] + "Id=" + authorizationid + sb.ToString());
            }
            return RedirectToAction(nameof(Index), new { appid = Appid });
        }
    }
}
