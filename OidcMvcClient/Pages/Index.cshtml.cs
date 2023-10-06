using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Net.Http.Headers;
using System.Net.Http;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;

namespace OidcMvcClient.Pages
{
    public class IndexModel : PageModel
    {
        private readonly ILogger<IndexModel> _logger;
        public string ResourceCallResult { get; set; } = "";
        public string IntrospectionResourceCallResult { get; set; } = "";

        public IndexModel(ILogger<IndexModel> logger)
        {
            _logger = logger;
        }

        public void OnGet()
        {
            if (User != null) return;
        }

        public async Task OnPostMakecall()
        {
            using var httpClient = new HttpClient();
            httpClient.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            var accessToken = await HttpContext.GetTokenAsync("access_token") ?? "";
            httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

            using HttpResponseMessage resp = await httpClient.GetAsync("https://localhost:7298/Claims/GetCalims");
            if (resp.IsSuccessStatusCode) 
            {
                ResourceCallResult = resp.StatusCode + ":" + await resp.Content.ReadAsStringAsync();
            }
            else
            {
                ResourceCallResult = resp.StatusCode + ":" + resp.ReasonPhrase ?? "ReasonPhrase is empty";
            }
            ResourceCallResult = ResourceCallResult.Replace("},{", "},\n{");
        }

        public async Task OnPostWebApiIntrospectionMakecall()
        {
            using var httpClient = new HttpClient();
            httpClient.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            var accessToken = await HttpContext.GetTokenAsync("access_token") ?? "";
            httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

            using HttpResponseMessage resp = await httpClient.GetAsync("https://localhost:7148/Claims/GetCalims");
            if (resp.IsSuccessStatusCode) 
            {
                IntrospectionResourceCallResult = resp.StatusCode + ":" + await resp.Content.ReadAsStringAsync();
            }
            else
            {
                IntrospectionResourceCallResult = resp.StatusCode + ":" + resp.ReasonPhrase ?? "ReasonPhrase is empty";
            }
            IntrospectionResourceCallResult = IntrospectionResourceCallResult.Replace("},{", "},\n{");
        }

        

    }
}