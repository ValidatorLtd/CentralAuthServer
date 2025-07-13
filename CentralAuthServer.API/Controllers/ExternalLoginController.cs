using CentralAuthServer.Core.Entities;
using CentralAuthServer.Core.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace CentralAuthServer.API.Controllers
{
    [Route("external-login")]
    public class ExternalLoginController : Controller
    {
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly IAuditLogger _auditLogger;

        public ExternalLoginController(
            SignInManager<ApplicationUser> signInManager,
            UserManager<ApplicationUser> userManager,
            IAuditLogger auditLogger)
        {
            _signInManager = signInManager;
            _userManager = userManager;
            _auditLogger = auditLogger;
        }

        [HttpGet("google")]
        public IActionResult GoogleLogin()
        {
            var redirectUrl = Url.Action("GoogleCallback", "ExternalLogin");
            var properties = _signInManager.ConfigureExternalAuthenticationProperties("Google", redirectUrl);
            return Challenge(properties, "Google");
        }

        [HttpGet("google-callback")]
        public async Task<IActionResult> GoogleCallback()
        {
            return await HandleExternalLoginCallback("Google");
        }

        [HttpGet("facebook")]
        public IActionResult FacebookLogin()
        {
            var redirectUrl = Url.Action("FacebookCallback", "ExternalLogin");
            var properties = _signInManager.ConfigureExternalAuthenticationProperties("Facebook", redirectUrl);
            return Challenge(properties, "Facebook");
        }

        [HttpGet("facebook-callback")]
        public async Task<IActionResult> FacebookCallback()
        {
            return await HandleExternalLoginCallback("Facebook");
        }

        [HttpGet("microsoft")]
        public IActionResult MicrosoftLogin()
        {
            var redirectUrl = Url.Action("MicrosoftCallback", "ExternalLogin");
            var properties = _signInManager.ConfigureExternalAuthenticationProperties("Microsoft", redirectUrl);
            return Challenge(properties, "Microsoft");
        }

        [HttpGet("microsoft-callback")]
        public async Task<IActionResult> MicrosoftCallback()
        {
            return await HandleExternalLoginCallback("Microsoft");
        }

        private async Task<IActionResult> HandleExternalLoginCallback(string provider)
        {
            var info = await _signInManager.GetExternalLoginInfoAsync();
            if (info == null || info.LoginProvider != provider)
                return Redirect("/login?error=external");

            // ✅ 1. Try direct sign-in (already linked)
            var result = await _signInManager.ExternalLoginSignInAsync(
                info.LoginProvider, info.ProviderKey, isPersistent: false);

            if (result.Succeeded)
            {
                var userId = info.Principal.FindFirstValue(ClaimTypes.NameIdentifier) ?? info.Principal.FindFirstValue(ClaimTypes.Email);
                if (!string.IsNullOrEmpty(userId))
                {
                    var user = await _userManager.FindByEmailAsync(userId);
                    if (user != null)
                    {
                        await _auditLogger.LogAsync(user.Id, "Login", provider, HttpContext);
                    }
                }
                return Redirect("/login-success");
            }

            // ✅ 2. Get email from external provider
            var email = info.Principal.FindFirstValue(ClaimTypes.Email);
            if (string.IsNullOrEmpty(email))
                return Redirect("/login?error=no-email");

            // ✅ 3. Find user by email
            var userByEmail = await _userManager.FindByEmailAsync(email);

            if (userByEmail != null)
            {
                // ✅ 4. Link external login to existing user (if not already linked)
                var existingLogins = await _userManager.GetLoginsAsync(userByEmail);
                if (!existingLogins.Any(l => l.LoginProvider == info.LoginProvider))
                {
                    var linkResult = await _userManager.AddLoginAsync(userByEmail, info);
                    if (!linkResult.Succeeded)
                        return Redirect("/login?error=link-failed");
                }

                await _signInManager.SignInAsync(userByEmail, isPersistent: false);
                await _auditLogger.LogAsync(userByEmail.Id, "Login", provider, HttpContext);
                return Redirect("/login-success");
            }

            // ✅ 5. No user found → create new
            var newUser = new ApplicationUser
            {
                Email = email,
                EmailConfirmed = true
            };

            var createResult = await _userManager.CreateAsync(newUser);
            if (!createResult.Succeeded)
                return Redirect("/login?error=create-failed");

            await _userManager.AddLoginAsync(newUser, info);
            await _signInManager.SignInAsync(newUser, isPersistent: false);
            await _auditLogger.LogAsync(newUser.Id, "Login", provider, HttpContext);

            return Redirect("/login-success");
        }
    }
}
