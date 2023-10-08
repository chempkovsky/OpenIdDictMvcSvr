using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Net.Http.Headers;
using System.Text.Json.Nodes;

namespace OidcWebApiResource.Controllers
{
    [ApiController]
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
        public async Task<string> GetRedirCalimsAsync()
        {
            using var httpClient = new HttpClient();
            httpClient.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            var accessToken = await HttpContext.GetTokenAsync("access_token") ?? "";
            httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
            using HttpResponseMessage resp = await httpClient.GetAsync("https://localhost:7148/Claims/GetCalims");
            if (resp.IsSuccessStatusCode)
            {
                return resp.StatusCode + ":" + await resp.Content.ReadAsStringAsync();
            }
            else
            {
                return resp.StatusCode + ":" + resp.ReasonPhrase ?? "ReasonPhrase is empty";
            }
        }

        [HttpGet]
        [Route("[controller]/GetToken")]
        public async Task<string> GetTokenAsync()
        {
            using var httpClient = new HttpClient();
            httpClient.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            var requestData = new[] {
                new KeyValuePair<string, string>("client_id", "OidcWebApiResourceGetToken"),
                new KeyValuePair<string, string>("client_secret", "OidcWebApiResourceGetToken_Secret"),
                new KeyValuePair<string, string>("grant_type", "client_credentials"),
                new KeyValuePair<string, string>("scope", "openid GetCalimsScp"),
                new KeyValuePair<string, string>("audience", "OidcWebApiIntrospectionResource"),
                new KeyValuePair<string, string>("audience", "OidcWebApiResource"),
            };
            using HttpResponseMessage resp = await httpClient.PostAsync("https://localhost:7067/connect/token", new FormUrlEncodedContent(requestData));
            if (resp.IsSuccessStatusCode)
            {
                var json = await resp.Content.ReadAsStringAsync();
                if (json != null) {
                    JsonNode? jo = JsonNode.Parse(json)?.AsObject();
                    if(jo != null)
                    {
                        var accessToken = jo["access_token"]?.ToString();
                        httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
                        using HttpResponseMessage w_resp = await httpClient.GetAsync("https://localhost:7148/Claims/GetCalims");
                        if (w_resp.IsSuccessStatusCode)
                        {
                            return w_resp.StatusCode + ":" + await w_resp.Content.ReadAsStringAsync();
                        }
                        else
                        {
                            return w_resp.StatusCode + ":" + w_resp.ReasonPhrase ?? "ReasonPhrase is empty";
                        }
                    }
                }
            }
            return resp.StatusCode + ":" + resp.ReasonPhrase ?? "ReasonPhrase is empty"; ;
        }
    }
}