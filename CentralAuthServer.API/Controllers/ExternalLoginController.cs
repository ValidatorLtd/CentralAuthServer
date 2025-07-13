using CentralAuthServer.Core.Entities;
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

        public ExternalLoginController(SignInManager<ApplicationUser> signInManager, UserManager<ApplicationUser> userManager)
        {
            _signInManager = signInManager;
            _userManager = userManager;
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
            var info = await _signInManager.GetExternalLoginInfoAsync();
            if (info == null) return Redirect("/login?error=external");

            var signInResult = await _signInManager.ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey, isPersistent: false);
            if (signInResult.Succeeded)
                return Redirect("/login-success");

            var email = info.Principal.FindFirstValue(ClaimTypes.Email);
            if (email == null) return Redirect("/login?error=no-email");

            var user = await _userManager.FindByEmailAsync(email);
            if (user == null)
            {
                user = new ApplicationUser
                {
                    UserName = email,
                    Email = email,
                    EmailConfirmed = true
                };
                await _userManager.CreateAsync(user);
            }

            await _userManager.AddLoginAsync(user, info);
            await _signInManager.SignInAsync(user, isPersistent: false);

            return Redirect("/login-success");
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
                return Redirect("/login-success");

            // ✅ 2. Get email from external provider
            var email = info.Principal.FindFirstValue(ClaimTypes.Email);
            if (string.IsNullOrEmpty(email))
                return Redirect("/login?error=no-email");

            // ✅ 3. Find user by email
            var user = await _userManager.FindByEmailAsync(email);

            if (user != null)
            {
                // ✅ 4. Link external login to existing user (if not already linked)
                var existingLogins = await _userManager.GetLoginsAsync(user);
                if (!existingLogins.Any(l => l.LoginProvider == info.LoginProvider))
                {
                    var linkResult = await _userManager.AddLoginAsync(user, info);
                    if (!linkResult.Succeeded)
                        return Redirect("/login?error=link-failed");
                }

                await _signInManager.SignInAsync(user, isPersistent: false);
                return Redirect("/login-success");
            }

            // ✅ 5. No user found → create new
            user = new ApplicationUser
            {
                Email = email,
                UserName = email,
                EmailConfirmed = true
            };

            var createResult = await _userManager.CreateAsync(user);
            if (!createResult.Succeeded)
                return Redirect("/login?error=create-failed");

            await _userManager.AddLoginAsync(user, info);
            await _signInManager.SignInAsync(user, isPersistent: false);
            return Redirect("/login-success");
        }


    }

}
