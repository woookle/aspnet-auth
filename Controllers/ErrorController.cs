using Microsoft.AspNetCore.Mvc;
using AuthApi.Models;

namespace AuthApi.Controllers
{
    [ApiController]
    [Route("api/auth")]
    public class ErrorController : ControllerBase
    {
        [HttpGet("unauthorized")]
        public IActionResult UnauthorizedAccess()
        {
            return Unauthorized(new ApiResponse 
            { 
                Success = false, 
                Message = "Authentication required" 
            });
        }

        [HttpGet("forbidden")]
        public IActionResult Forbidden()
        {
            return Forbid();
        }
    }
}