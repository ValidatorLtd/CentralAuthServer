using Microsoft.AspNetCore.Identity;

namespace CentralAuthServer.Core.Entities;

public class ApplicationUser : IdentityUser
{
    public string? TwoFactorCode { get; set; }
    public DateTime? TwoFactorExpires { get; set; }
}
