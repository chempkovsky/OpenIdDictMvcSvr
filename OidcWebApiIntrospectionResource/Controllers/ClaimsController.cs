using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

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
        public IEnumerable<ClaimDto> GetRedirCalims()
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


    }
}