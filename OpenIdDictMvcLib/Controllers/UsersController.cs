using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Localization;
using OpenIdDictMvcLib.Dto;
using OpenIdDictMvcLib.Localizers;
using OpenIdDictMvcContext.Data;
using Microsoft.Extensions.Logging;
using Microsoft.AspNetCore.Authorization;

namespace OpenIdDictMvcLib.Controllers
{
    [Authorize(Roles = $"{OidcIdentityConsts.AdminRoleName}")]
    public class UsersController : Controller
    {
        private readonly UserManager<OidcIdentityUser> _userManager;
        private readonly ILogger<IdentityUserDto> _logger;
        private readonly IStringLocalizer<UserLocalizerResource> _sharedLocalizer;


        public UsersController(UserManager<OidcIdentityUser> userManager,
            ILogger<IdentityUserDto> logger,
            IStringLocalizer<UserLocalizerResource> SharedLocalizer)
        {
            _userManager = userManager;
            _logger = logger;
            _sharedLocalizer = SharedLocalizer;
        }

        // GET: Users
        public async Task<IActionResult> Index(string? searchby = null, string? searchstr = null, int? currpg = null)
        {
            // return Problem("Entity set 'ApplicationDbContext.IdentityUserRoleDto'  is null.");
            PageDto pager = new () { PageSize = 10 };
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
                switch(searchby)
                {
                    case "1":
                        SearchById = 1;
                        break;
                    case "2":
                        SearchById = 2;
                        break;
                }
            }
            ViewBag.SearchById = SearchById.ToString();
            ViewBag.SearchBy = new List<SelectListItem>() {
                new SelectListItem(){ Text = _sharedLocalizer["Filter by User Id"], Value = "0", Selected = SearchById == 0 },
                new SelectListItem(){ Text = _sharedLocalizer["Filter by User Name"], Value = "1", Selected = SearchById == 1 },
                new SelectListItem(){ Text = _sharedLocalizer["Filter by User Email"], Value = "2", Selected = SearchById == 2 }
            };
            var query = _userManager.Users;
            if (!string.IsNullOrEmpty(searchstr))
            {
                ViewBag.SearchString = searchstr;
                switch (SearchById)
                {
                    case 1:
                        string qs1 = searchstr.ToUpper();
                        query = query.Where(r => r.NormalizedUserName.StartsWith(qs1));
                        break;
                    case 2:
                        string qs2 = searchstr.ToUpper();
                        query = query.Where(r => r.NormalizedEmail.StartsWith(qs2));
                        break;
                    default:
                        query = query.Where(r => r.Id == searchstr);
                        break;
                }
            } else
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
            
            if (total < 1)
            {
                ViewBag.Pager = pager;
                return View(new List<IdentityUserDto>());
            }

            if (SearchById == 1)
            {
                query = query.OrderBy(r => r.NormalizedUserName);
            }
            else if (SearchById == 2)
            {
                query = query.OrderBy(r => r.NormalizedEmail);
            } else
            {
                query = query.OrderBy(r => r.Id);
            }

            if (pager.CurrentPage > 1)
            {

                query = query.Skip((pager.CurrentPage - 1) * pager.PageSize);
            }
            ViewBag.Pager = pager;
            return View(await query.AsNoTracking().Take(pager.PageSize).Select(itm => new IdentityUserDto()
            {
                Id = itm.Id,
                UserName = itm.UserName,
                NormalizedUserName = itm.NormalizedUserName,
                Email = itm.Email,
                NormalizedEmail = itm.NormalizedEmail,
                EmailConfirmed = itm.EmailConfirmed,
                ConcurrencyStamp = itm.ConcurrencyStamp,
                PhoneNumber = itm.PhoneNumber,
                PhoneNumberConfirmed = itm.PhoneNumberConfirmed,
                TwoFactorEnabled = itm.TwoFactorEnabled,
                LockoutEnd = itm.LockoutEnd,
                LockoutEnabled = itm.LockoutEnabled,
            }).ToListAsync());
        }

        // GET: Users/Details/5
        public async Task<IActionResult> Details(string id)
        {
            if (id == null)
            {
                return NotFound();
            }
            var identityUserDto = await _userManager.FindByIdAsync(id);
            if (identityUserDto == null)
            {
                return NotFound();
            }
            var rslt = DataMap(identityUserDto);
            return View(rslt);
        }


        // GET: Users/Delete/5
        public async Task<IActionResult> Delete(string id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var identityUserDto = await _userManager.FindByIdAsync(id);
            if (identityUserDto == null)
            {
                return NotFound();
            }
            var rslt = DataMap(identityUserDto);
            return View(rslt);
        }

        // POST: Users/Delete/5
        [HttpPost, ActionName("Delete")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteConfirmed(string id)
        {
            var aUser = await _userManager.FindByIdAsync(id);
            if (aUser == null)
            {
                return NotFound();
            }
            var uroles = await _userManager.GetRolesAsync(aUser);
            if(uroles != null)
            {
                if(uroles.Count > 0)
                {
                    _ = await _userManager.RemoveFromRolesAsync(aUser, uroles);
                }
            }

            var rslt = await _userManager.DeleteAsync(aUser);
            if (rslt.Succeeded)
            {
                _logger.LogInformation("Deleted a user with ID:" + aUser.Id + " " + "and a name:" + aUser.NormalizedUserName);
            }
            else
            {
                string ExceptionStr = "";
                if (rslt.Errors != null)
                {
                    foreach (var e in rslt.Errors)
                        ExceptionStr = e.Code + ":" + e.Description;
                }
                _logger.LogInformation("Could not delete a user with ID:" + aUser.Id + " " + "and a name:" + aUser.NormalizedUserName + ": " + ExceptionStr);
                throw new InvalidOperationException(ExceptionStr);
            }
            return RedirectToAction(nameof(Index));
        }

        protected IdentityUserDto DataMap(OidcIdentityUser identityUserDto) {
            return new IdentityUserDto
            {
                Id = identityUserDto.Id,
                UserName = identityUserDto.Id,
                NormalizedUserName = identityUserDto.NormalizedUserName,
                Email = identityUserDto.Email,
                NormalizedEmail = identityUserDto.NormalizedEmail,
                EmailConfirmed = identityUserDto.EmailConfirmed,
                PasswordHash = identityUserDto.PasswordHash,
                SecurityStamp = identityUserDto.SecurityStamp,
                ConcurrencyStamp = identityUserDto.ConcurrencyStamp,
                PhoneNumber = identityUserDto.PhoneNumber,
                PhoneNumberConfirmed = identityUserDto.PhoneNumberConfirmed,
                TwoFactorEnabled = identityUserDto.TwoFactorEnabled,
                LockoutEnd = identityUserDto.LockoutEnd,
                LockoutEnabled = identityUserDto.LockoutEnabled
            };
        }
    }
}
