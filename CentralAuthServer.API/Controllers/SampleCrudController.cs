using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace CentralAuthServer.API.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class SampleCrudController : ControllerBase
    {
        [Authorize(Roles = "Admin")]
        [HttpGet("admin-only")]
        public IActionResult GetAdminData() => Ok("Only Admins can see this!");

        // New method accessible to all authenticated users
        [Authorize]
        [HttpGet("authorized-only")]
        public IActionResult GetAuthorizedData() => Ok("This data is accessible to authorized users!");

        // New method accessible to all requests (authenticated and unauthenticated)
        [AllowAnonymous]
        [HttpGet("open-to-all")]
        public IActionResult GetOpenData() => Ok("This data is accessible to everyone!");
    }
}
