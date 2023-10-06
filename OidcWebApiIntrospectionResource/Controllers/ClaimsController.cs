using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Net.Http.Headers;

namespace OidcWebApiIntrospectionResource.Controllers
{
    [ApiController]
    [Authorize]
    public class ClaimsController : ControllerBase
    {

        private readonly ILogger<ClaimsController> _logger;

        public ClaimsController(ILogger<ClaimsController> logger)
        {
            _logger = logger;
        }

        [HttpGet]
        [Route("[controller]/GetCalims")]
        [Authorize(Policy = "HasGetCalimsScope")]
        public IEnumerable<ClaimDto> GetCalims()
        {
            var rslt = User.Claims.Select(c => new ClaimDto
            {
                Value = c.Value,
                Type = c.Type,
                //Issuer = c.Issuer,
                //OriginalIssuer = c.Issuer,
                //ValueType = c.ValueType
            }).ToList();
            return rslt;
        }

        [HttpGet]
        [Route("[controller]/GetRedirCalims")]
        [Authorize(Policy = "HasGetRedirScope")]
        public async Task<string> GetRedirCalims()
        {
            using var httpClient = new HttpClient();
            httpClient.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            var accessToken = await HttpContext.GetTokenAsync("access_token") ?? "";
            httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
            using HttpResponseMessage resp = await httpClient.GetAsync("https://localhost:7298/Claims/GetCalims");
            if (resp.IsSuccessStatusCode) 
            {
                return resp.StatusCode + ":" + await resp.Content.ReadAsStringAsync();
            }
            else
            {
                return resp.StatusCode + ":" + resp.ReasonPhrase ?? "ReasonPhrase is empty";
            }
        }


    }
}