using CentralAuthServer.API.DTOs;
using CentralAuthServer.Core.Entities;
using CentralAuthServer.Infrastructure;
using CentralAuthServer.Infrastructure.Entities;
using CentralAuthServer.Infrastructure.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using OtpNet;
using QRCoder;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IConfiguration _config;
    private readonly CentralAuthServer.Core.Services.IEmailSender _emailSender;
    private readonly AuthDbContext _dbContext;

    public AuthController(UserManager<ApplicationUser> userManager, IConfiguration config,
        CentralAuthServer.Core.Services.IEmailSender emailSender, AuthDbContext dbContext)
    {
        _userManager = userManager;
        _config = config;
        _emailSender = emailSender;
        _dbContext = dbContext;
    }

    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] RegisterDto model)
    {
        if (!ModelState.IsValid)
            return BadRequest(ModelState);

        var user = new ApplicationUser
        {
            UserName = model.Email,
            Email = model.Email,
        };

        var result = await _userManager.CreateAsync(user, model.Password);

        if (!result.Succeeded)
            return BadRequest(result.Errors);

        // Assign default role
        await _userManager.AddToRoleAsync(user, "User"); // Default role

        // Generate email confirmation token
        var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
        var confirmationLink = Url.Action(
            nameof(ConfirmEmail),
            "Auth",
            new { userId = user.Id, token },
            Request.Scheme);

        // TODO: Send the confirmation link via email
        await _emailSender.SendEmailAsync(user.Email, "Confirm your email",
            $"Please confirm your account by <a href='{confirmationLink}'>clicking here</a>");

        return Ok(new
        {
            message = "Registration successful. Please check your email to confirm your account."
        });
    }


    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginDto dto)
    {
        var user = await _userManager.FindByEmailAsync(dto.Email);
        if (user == null || !await _userManager.CheckPasswordAsync(user, dto.Password))
            return Unauthorized("Invalid credentials.");

        if (!await _userManager.IsEmailConfirmedAsync(user))
            return Unauthorized("Email not confirmed.");

        switch (user.MfaMethod)
        {
            case MfaMethod.Email:
                // Generate and send 2FA email code
                var emailCode = new Random().Next(100000, 999999).ToString();
                user.TwoFactorCode = emailCode;
                user.TwoFactorExpires = DateTime.UtcNow.AddMinutes(5);
                await _dbContext.SaveChangesAsync();

                await _emailSender.SendEmailAsync(user.Email!, "Your 2FA Code", $"Your code is: {emailCode}");

                return Ok(new
                {
                    requires2FA = true,
                    method = "Email",
                    message = "A 2FA code has been sent to your email."
                });

            case MfaMethod.TOTP:
                return Ok(new
                {
                    requires2FA = true,
                    method = "TOTP",
                    message = "Enter the code from your Authenticator app."
                });

            case MfaMethod.None:
            default:
                // No MFA, proceed with login
                var jwtResult = await GenerateJwtAsync(user);
                var refreshToken = new RefreshToken
                {
                    Token = Guid.NewGuid().ToString("N"),
                    JwtId = jwtResult.JwtId,
                    CreatedAt = DateTime.UtcNow,
                    ExpiresAt = DateTime.UtcNow.AddDays(7),
                    UserId = user.Id,
                    IPAddress = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown",
                    DeviceInfo = Request.Headers["User-Agent"].ToString()
                };

                await _dbContext.RefreshTokens.AddAsync(refreshToken);
                await _dbContext.SaveChangesAsync();

                return Ok(new
                {
                    accessToken = jwtResult.Token,
                    refreshToken = refreshToken.Token
                });
        }
    }


    [HttpPost("logout")]
    public async Task<IActionResult> Logout([FromBody] RevokeTokenRequest dto)
    {
        var token = await _dbContext.RefreshTokens
            .FirstOrDefaultAsync(t => t.Token == dto.RefreshToken);

        if (token == null) return NotFound("Refresh token not found.");
        if (token.Revoked) return BadRequest("Token already revoked.");

        token.Revoked = true;
        await _dbContext.SaveChangesAsync();

        return Ok("Logged out successfully.");
    }

    [HttpPost("verify-2fa")]
    public async Task<IActionResult> Verify2FA([FromBody] Verify2FADto dto)
    {
        var user = await _userManager.FindByEmailAsync(dto.Email);
        if (user == null || user.TwoFactorCode != dto.Code || user.TwoFactorExpires < DateTime.UtcNow)
            return Unauthorized("Invalid or expired 2FA code.");

        // Clear the code
        user.TwoFactorCode = null;
        user.TwoFactorExpires = null;

        var jwt = await GenerateJwtAsync(user);
        var refreshToken = new RefreshToken
        {
            Token = Guid.NewGuid().ToString("N"),
            JwtId = jwt.JwtId,
            CreatedAt = DateTime.UtcNow,
            ExpiresAt = DateTime.UtcNow.AddDays(7),
            UserId = user.Id,
            IPAddress = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            DeviceInfo = Request.Headers["User-Agent"].ToString()
        };

        await _dbContext.RefreshTokens.AddAsync(refreshToken);
        await _dbContext.SaveChangesAsync();

        return Ok(new
        {
            accessToken = jwt.Token,
            refreshToken = refreshToken.Token
        });
    }

    [Authorize]
    [HttpGet("mfa/setup")]
    public IActionResult SetupTOTP()
    {
        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        var user = _dbContext.Users.FirstOrDefault(u => u.Id == userId);
        if (user == null) return Unauthorized();

        var secret = Base32Encoding.ToString(KeyGeneration.GenerateRandomKey(20));
        user.TOTPSecret = secret;
        _dbContext.SaveChanges();

        var issuer = "YourAppName";
        var barcodeUrl = $"otpauth://totp/{issuer}:{user.Email}?secret={secret}&issuer={issuer}";

        using var qrGenerator = new QRCodeGenerator();
        using var qrCodeData = qrGenerator.CreateQrCode(barcodeUrl, QRCodeGenerator.ECCLevel.Q);
        using var qrCode = new PngByteQRCode(qrCodeData);
        var qrCodeBytes = qrCode.GetGraphic(20);

        return File(qrCodeBytes, "image/png");
    }

    [Authorize]
    [HttpPost("mfa/verify-totp")]
    public IActionResult VerifyTOTP([FromBody] VerifyTOTPDto dto)
    {
        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        var user = _dbContext.Users.FirstOrDefault(u => u.Id == userId);
        if (user == null || string.IsNullOrEmpty(user.TOTPSecret)) return BadRequest("Not configured.");

        var totp = new Totp(Base32Encoding.ToBytes(user.TOTPSecret));
        var isValid = totp.VerifyTotp(dto.Code, out _, VerificationWindow.RfcSpecifiedNetworkDelay);

        if (!isValid)
            return Unauthorized("Invalid code.");

        // Optionally mark TOTP as verified or continue login flow
        return Ok("MFA code verified.");
    }

    [Authorize]
    [HttpPost("mfa/set-method")]
    public async Task<IActionResult> SetMfaMethod([FromBody] SetMfaMethodDto dto)
    {
        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        var user = await _dbContext.Users.FindAsync(userId);
        if (user == null) return Unauthorized();

        user.MfaMethod = dto.Method;
        await _dbContext.SaveChangesAsync();

        return Ok($"MFA method set to {dto.Method}");
    }

    [Authorize]
    [HttpPost("revoke-all")]
    public async Task<IActionResult> RevokeAll()
    {
        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (userId == null) return Unauthorized();

        var tokens = await _dbContext.RefreshTokens
            .Where(t => t.UserId == userId && !t.Revoked)
            .ToListAsync();

        foreach (var token in tokens)
            token.Revoked = true;

        await _dbContext.SaveChangesAsync();

        return Ok("All sessions have been revoked.");
    }

    [Authorize(Roles = "Admin")]
    [HttpPost("admin/revoke/{userId}")]
    public async Task<IActionResult> AdminRevoke(string userId)
    {
        var tokens = await _dbContext.RefreshTokens
            .Where(t => t.UserId == userId && !t.Revoked)
            .ToListAsync();

        foreach (var token in tokens)
            token.Revoked = true;

        await _dbContext.SaveChangesAsync();
        return Ok($"All sessions for user {userId} revoked.");
    }

    [HttpGet("confirm-email")]
    public async Task<IActionResult> ConfirmEmail(string userId, string token)
    {
        var user = await _userManager.FindByIdAsync(userId);
        if (user == null)
            return BadRequest("Invalid user.");

        var result = await _userManager.ConfirmEmailAsync(user, token);
        if (result.Succeeded)
            return Ok("Email confirmed successfully!");

        return BadRequest("Email confirmation failed.");
    }

    [HttpPost("forgot-password")]
    public async Task<IActionResult> ForgotPassword(ForgotPasswordDto dto)
    {
        var user = await _userManager.FindByEmailAsync(dto.Email);
        if (user == null) return Ok(); // Don't reveal user existence

        var token = await _userManager.GeneratePasswordResetTokenAsync(user);
        var resetLink = $"{_config["Frontend:BaseUrl"]}/reset-password?email={user.Email}&token={Uri.EscapeDataString(token)}";

        await _emailSender.SendEmailAsync(user.Email, "Reset your password", $"Click to reset: {resetLink}");

        return Ok();
    }

    [HttpPost("reset-password")]
    public async Task<IActionResult> ResetPassword(ResetPasswordDto dto)
    {
        var user = await _userManager.FindByEmailAsync(dto.Email);
        if (user == null) return BadRequest("Invalid request.");

        var result = await _userManager.ResetPasswordAsync(user, dto.Token, dto.NewPassword);
        if (!result.Succeeded) return BadRequest(result.Errors);

        return Ok("Password has been reset successfully.");
    }

    private async Task<JwtResult> GenerateJwtAsync(ApplicationUser user)
    {
        var userRoles = await _userManager.GetRolesAsync(user);
        var roleClaims = userRoles.Select(r => new Claim(ClaimTypes.Role, r));

        var jwtId = Guid.NewGuid().ToString();
        var claims = new List<Claim>
        {
            new Claim(JwtRegisteredClaimNames.Sub, user.Id),
            new Claim(JwtRegisteredClaimNames.Email, user.Email!),
            new Claim(ClaimTypes.Name, user.UserName!),
            new Claim(JwtRegisteredClaimNames.Jti, jwtId)
        };
        claims.AddRange(roleClaims);

        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:Key"]!));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var token = new JwtSecurityToken(
            issuer: _config["Jwt:Issuer"],
            audience: _config["Jwt:Audience"],
            claims: claims,
            expires: DateTime.UtcNow.AddMinutes(30),
            signingCredentials: creds
        );

        return new JwtResult
        {
            Token = new JwtSecurityTokenHandler().WriteToken(token),
            JwtId = jwtId
        };
    }


}
