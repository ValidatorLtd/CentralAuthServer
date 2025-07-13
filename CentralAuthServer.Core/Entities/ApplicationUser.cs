using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations;

namespace CentralAuthServer.Core.Entities;

public class ApplicationUser : IdentityUser
{

    [Required]
    [EmailAddress]    
    [StringLength(256)]
    public override string Email { get; set; }


    public string? TwoFactorCode { get; set; }
    public DateTime? TwoFactorExpires { get; set; }
    public MfaMethod MfaMethod { get; set; } = MfaMethod.None;
    public string? TOTPSecret { get; set; }
    public Guid TenantId { get; set; }
    public Tenant Tenant { get; set; } = null!;
}

public enum MfaMethod
{
    None,
    Email,
    TOTP
}
