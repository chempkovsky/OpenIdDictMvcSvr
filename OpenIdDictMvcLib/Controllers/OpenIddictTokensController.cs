using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Localization;
using OpenIddict.Abstractions;
using OpenIdDictMvcContext.Data;
using OpenIdDictMvcLib.Dto;
using OpenIdDictMvcLib.Localizers;
using System.Text;
using Microsoft.Extensions.Logging;

namespace OpenIdDictMvcLib.Controllers
{
    public class OpenIddictTokensController : Controller
    {
        private readonly ApplicationDbContext _context;
        private readonly IOpenIddictTokenManager _tokenManager;
        private readonly ILogger<OpenIddictTokenDescriptorDto> _logger;
        private readonly IStringLocalizer<OpenIddictTokenLocalizerResource> _sharedLocalizer;
        private readonly IOpenIddictApplicationManager _applicationManager;
        private readonly IOpenIddictAuthorizationManager _authorizationManager;

        public OpenIddictTokensController(ApplicationDbContext context,
            IOpenIddictTokenManager tokenManager,
            IOpenIddictApplicationManager applicationManager,
            IOpenIddictAuthorizationManager authorizationManager,
            ILogger<OpenIddictTokenDescriptorDto> logger,
            IStringLocalizer<OpenIddictTokenLocalizerResource> sharedLocalizer)
        {
            _context = context;
            _tokenManager = tokenManager;
            _logger = logger;
            _sharedLocalizer = sharedLocalizer;
            _applicationManager = applicationManager;
            _authorizationManager = authorizationManager;
        }

        public async Task<IActionResult> Index(string idtype, string prntid, int? currpg = null)
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
            ViewBag.IdType = idtype;
            ViewBag.PrntId = prntid;

            var dbtks = _context.Set<OidcToken>();
            if (dbtks == null)
            {
                return Problem(_sharedLocalizer["Entity set ApplicationDbContext.OidcToken is null."]);
            }
            var query = dbtks.AsNoTracking();
            if (idtype == "auth")
            {
                ViewBag.IdType = idtype;
                var auth = await _authorizationManager.FindByIdAsync(prntid);
                if (auth == null) { return NotFound(); }
                ViewBag.AppId = await _authorizationManager.GetApplicationIdAsync(auth);
                query = query.Where(t => t.Authorization!.Id == prntid);
            }
            else 
            {
                ViewBag.IdType = "app";
                var app = await _applicationManager.FindByIdAsync(prntid);
                if (app == null) { return NotFound(); }
                ViewBag.AppId = await _applicationManager.GetIdAsync(app);
                query = query.Where(t => t.Application!.Id == prntid);
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
                return View(new List<OpenIddictTokenDto>());
            }
            if (pager.CurrentPage > 1)
            {
                query = query.OrderBy(a => a.Id).Skip((pager.CurrentPage - 1) * pager.PageSize);
            }
            ViewBag.Pager = pager;
            return View(await query.AsNoTracking().Take(pager.PageSize).Select(itm => new OpenIddictTokenDto()
            {
                TokenId = itm.Id,
                CreationDate = itm.CreationDate,
                ExpirationDate = itm.ExpirationDate,
                RedemptionDate = itm.RedemptionDate,
                ReferenceId = itm.ReferenceId,
                Status = itm.Status,
                Subject = itm.Subject,
                TokenType = itm.Type
            }).ToListAsync());
        }


        // GET: OpenIddictTokens/Details/5
        public async Task<IActionResult> Details(string idtype, string prntid, string tokenid)
        {
            if (string.IsNullOrEmpty(tokenid) || string.IsNullOrEmpty(idtype) || string.IsNullOrEmpty(prntid))
            {
                return NotFound();
            }
            ViewBag.IdType = idtype;
            ViewBag.PrntId = prntid;
            ViewBag.TokenId = tokenid;
            var tkn = await _tokenManager.FindByIdAsync(tokenid);
            if(tkn == null)
            {
                return NotFound();
            }
            OpenIddictTokenDto rslt = new OpenIddictTokenDto() {
                TokenId = await _tokenManager.GetIdAsync(tkn),
                ApplicationId = await _tokenManager.GetApplicationIdAsync(tkn),
                AuthorizationId = await _tokenManager.GetAuthorizationIdAsync(tkn),
                CreationDate = await _tokenManager.GetCreationDateAsync(tkn),
                ExpirationDate = await _tokenManager.GetExpirationDateAsync(tkn),
                RedemptionDate = await _tokenManager.GetRedemptionDateAsync(tkn),
                ReferenceId = await _tokenManager.GetReferenceIdAsync(tkn),
                Status = await _tokenManager.GetStatusAsync(tkn),
                Subject = await _tokenManager.GetSubjectAsync(tkn),
                TokenType = await _tokenManager.GetTypeAsync(tkn),
            };
            ViewBag.AppId = rslt.ApplicationId;
            return View(rslt);
        }


        // GET: OpenIddictTokens/Delete/5
        public async Task<IActionResult> Delete(string idtype, string prntid, string tokenid)
        {
            if (string.IsNullOrEmpty(tokenid) || string.IsNullOrEmpty(idtype) || string.IsNullOrEmpty(prntid))
            {
                return NotFound();
            }
            var tkn = await _tokenManager.FindByIdAsync(tokenid);
            if (tkn == null)
            {
                return NotFound();
            }
            ViewBag.IdType = idtype;
            ViewBag.PrntId = prntid;
            ViewBag.TokenId = tokenid;

            OpenIddictTokenDto rslt = new OpenIddictTokenDto()
            {
                TokenId = await _tokenManager.GetIdAsync(tkn),
                ApplicationId = await _tokenManager.GetApplicationIdAsync(tkn),
                AuthorizationId = await _tokenManager.GetAuthorizationIdAsync(tkn),
                CreationDate = await _tokenManager.GetCreationDateAsync(tkn),
                ExpirationDate = await _tokenManager.GetExpirationDateAsync(tkn),
                RedemptionDate = await _tokenManager.GetRedemptionDateAsync(tkn),
                ReferenceId = await _tokenManager.GetReferenceIdAsync(tkn),
                Status = await _tokenManager.GetStatusAsync(tkn),
                Subject = await _tokenManager.GetSubjectAsync(tkn),
                TokenType = await _tokenManager.GetTypeAsync(tkn),
            };
            ViewBag.AppId = rslt.ApplicationId;
            return View(rslt);
        }

        // POST: OpenIddictTokens/Delete/5
        [HttpPost, ActionName("Delete")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteConfirmed(string idtype, string prntid, string tokenid)
        {
            if (string.IsNullOrEmpty(tokenid) || string.IsNullOrEmpty(idtype) || string.IsNullOrEmpty(prntid))
            {
                return NotFound();
            }
            var tkn = await _tokenManager.FindByIdAsync(tokenid);
            if (tkn == null)
            {
                return NotFound();
            }
            try
            {
                await _tokenManager.DeleteAsync(tkn);

            } catch (Exception ex)
            {
                Exception? wex = ex;
                StringBuilder sb = new();
                while (wex != null)
                {
                    sb.Append(wex.Message);
                    wex = wex.InnerException;
                }
                _logger.LogInformation("Could not Delete a token with ID:" + tokenid );
                ModelState.AddModelError("Delete", sb.ToString());
                OpenIddictTokenDto rslt = new OpenIddictTokenDto()
                {
                    TokenId = await _tokenManager.GetIdAsync(tkn),
                    ApplicationId = await _tokenManager.GetApplicationIdAsync(tkn),
                    AuthorizationId = await _tokenManager.GetAuthorizationIdAsync(tkn),
                    CreationDate = await _tokenManager.GetCreationDateAsync(tkn),
                    ExpirationDate = await _tokenManager.GetExpirationDateAsync(tkn),
                    RedemptionDate = await _tokenManager.GetRedemptionDateAsync(tkn),
                    ReferenceId = await _tokenManager.GetReferenceIdAsync(tkn),
                    Status = await _tokenManager.GetStatusAsync(tkn),
                    Subject = await _tokenManager.GetSubjectAsync(tkn),
                    TokenType = await _tokenManager.GetTypeAsync(tkn),
                };
                return View(rslt);
            }
            return RedirectToAction(nameof(Index), new { idtype = idtype, prntid = prntid });
        }



    }
}
