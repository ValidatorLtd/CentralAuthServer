using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using CentralAuthServer.Core.Entities;
using Microsoft.AspNetCore.Identity;

namespace CentralAuthServer.Infrastructure;

public class AuthDbContext : IdentityDbContext<ApplicationUser>
{
    public AuthDbContext(DbContextOptions<AuthDbContext> options) : base(options) { }
}
